using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Net;
using System.IO;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using AsyncSocketSample;

namespace dlech.PageantSharp
{
  /// <summary>
  /// ssh-agent for linux
  /// </summary>
  /// <remarks>
  /// Code based on ssh-agent.c from OpenBSD/OpenSSH and
  /// http://msdn.microsoft.com/en-us/library/system.net.sockets.socketasynceventargs.aspx
  /// </remarks>
  public class LinAgent : Agent
  {
    /* constants */

    /* Name of the environment variable containing the process ID of the
     * authentication agent. */
    public static string SSH_AGENTPID_ENV_NAME = "SSH_AGENT_PID";
    /* Name of the environment variable containing the pathname of the
     * authentication socket. */
    public static string SSH_AUTHSOCKET_ENV_NAME = "SSH_AUTH_SOCK";
    /* Listen backlog for sshd, ssh-agent and forwarding sockets */
    private static int SSH_LISTEN_BACKLOG = 128;
    private static string TMPDIR_TEMPLATE = "ssh-XXXXXX";
    private static int maxNumConnections = 10;
    private static int receiveBufferSize = 4096;



    /* global variables */
    private string socketDir; // temporary directory that contains domain socket file
    private Socket socket;
    private BufferManager bufferManager;
    private SocketAsyncEventArgsPool socketAsyncEventArgsPool;
    private int numConnections;
    private Semaphore maxNumberAcceptedClients;
    private bool isDisposed;
    /* external */

    [DllImport("libc", SetLastError = true)]
    private static extern string mkdtemp(IntPtr template);

    /* constructor */

    public LinAgent(CallBacks aCallBacks)
      : base(aCallBacks)
    {
      // TODO load Mono.Unix assembly so that we can run on windows.

      if (Environment.GetEnvironmentVariable(LinAgent.SSH_AUTHSOCKET_ENV_NAME) != null) {
        throw new Exception("ssh-agent is already running");
      }

      this.isDisposed = false;

      string pid = Process.GetCurrentProcess().Id.ToString();

      this.socketDir = Path.GetTempPath() ?? "/tmp";
      this.socketDir = Path.Combine(this.socketDir, TMPDIR_TEMPLATE);
      IntPtr socketDirPtr = Marshal.StringToCoTaskMemAnsi(this.socketDir);
      this.socketDir = mkdtemp(socketDirPtr);
      Marshal.ZeroFreeCoTaskMemAnsi(socketDirPtr);
      if (this.socketDir == null) {
        int errno = Marshal.GetLastWin32Error();
        throw new Exception(errno.ToString());
      }
      string socketPath = Path.Combine(this.socketDir, "agent." + pid);

      this.socket = new Socket(AddressFamily.Unix, SocketType.Stream,
                          ProtocolType.Unspecified);
      Mono.Unix.UnixEndPoint endPoint = new Mono.Unix.UnixEndPoint(socketPath);
      Mono.Unix.Native.FilePermissions prevUmask =
        Mono.Unix.Native.Syscall.umask(
          Mono.Unix.Native.FilePermissions.S_IXUSR |
          Mono.Unix.Native.FilePermissions.S_IRWXG |
          Mono.Unix.Native.FilePermissions.S_IRWXO);
      try {
        this.socket.Bind(endPoint);
      } catch {
        throw;
      } finally {
        Mono.Unix.Native.Syscall.umask(prevUmask);
      }
      this.socket.Listen(SSH_LISTEN_BACKLOG);

      Environment.SetEnvironmentVariable(LinAgent.SSH_AUTHSOCKET_ENV_NAME, socketPath);
      Environment.SetEnvironmentVariable(LinAgent.SSH_AGENTPID_ENV_NAME, pid);

      // TODO find a way to export environment variables for entire session
      // not just this process.

      this.numConnections = LinAgent.maxNumConnections;
      this.bufferManager = new BufferManager(receiveBufferSize * numConnections * 2,
                                             receiveBufferSize);
      this.socketAsyncEventArgsPool = new SocketAsyncEventArgsPool(numConnections);
      this.maxNumberAcceptedClients = new Semaphore(numConnections, numConnections);

      this.bufferManager.InitBuffer();
      SocketAsyncEventArgs socketAsyncEventArgs;
      for (int i = 0; i < this.numConnections; i++) {
        //Pre-allocate a set of reusable SocketAsyncEventArgs
        socketAsyncEventArgs = new SocketAsyncEventArgs();
        socketAsyncEventArgs.Completed += new EventHandler<SocketAsyncEventArgs>(IO_Completed);
        socketAsyncEventArgs.UserToken = new AsyncUserToken();

        // assign a byte buffer from the buffer pool to the SocketAsyncEventArg object
        this.bufferManager.SetBuffer(socketAsyncEventArgs);

        // add SocketAsyncEventArg to the pool
        this.socketAsyncEventArgsPool.Push(socketAsyncEventArgs);
      }

      StartAccept(null);
    }

    // Begins an operation to accept a connection request from the client
    // 
    // <param name="acceptEventArg">The context object to use when issuing 
    // the accept operation on the server's listening socket</param> 
    public void StartAccept(SocketAsyncEventArgs acceptEventArg)
    {
      if (acceptEventArg == null) {
        acceptEventArg = new SocketAsyncEventArgs();
        acceptEventArg.Completed += new EventHandler<SocketAsyncEventArgs>(AcceptEventArg_Completed);
      } else {
        // socket must be cleared since the context object is being reused
        acceptEventArg.AcceptSocket = null;
      }

      this.maxNumberAcceptedClients.WaitOne();
      if (!this.isDisposed) {
        bool willRaiseEvent = this.socket.AcceptAsync(acceptEventArg);
        if (!willRaiseEvent) {
          ProcessAccept(acceptEventArg);
        }
      }
    }

    // This method is the callback method associated with Socket.AcceptAsync
    // operations and is invoked when an accept operation is complete 
    // 
    void AcceptEventArg_Completed(object sender, SocketAsyncEventArgs e)
    {
      ProcessAccept(e);
    }

    private void ProcessAccept(SocketAsyncEventArgs e)
    {
      // Get the socket for the accepted client connection and put it into the  
      //ReadEventArg object user token
      SocketAsyncEventArgs readEventArgs = this.socketAsyncEventArgsPool.Pop();
      ((AsyncUserToken)readEventArgs.UserToken).Socket = e.AcceptSocket;

      // As soon as the client is connected, post a receive to the connection 
      bool willRaiseEvent = e.AcceptSocket.ReceiveAsync(readEventArgs);
      if (!willRaiseEvent) {
        ProcessReceive(readEventArgs);
      }

      // Accept the next connection request
      StartAccept(e);
    }

    // This method is called whenever a receive or send operation is completed on a socket  
    // 
    // <param name="e">SocketAsyncEventArg associated with the completed receive operation</param>
    void IO_Completed(object sender, SocketAsyncEventArgs e)
    {
      // determine which type of operation just completed and call the associated handler 
      switch (e.LastOperation) {
        case SocketAsyncOperation.Receive:
          ProcessReceive(e);
          break;
        case SocketAsyncOperation.Send:
          ProcessSend(e);
          break;
        default:
          throw new ArgumentException("The last operation completed on the socket was not a receive or send");
      }
    }

    /// <summary>
    /// This method is invoked when an asynchronous receive operation completes.
    /// If the remote host closed the connection, then the socket is closed.
    /// If data was received then the data is echoed back to the client.
    /// </summary>
    private void ProcessReceive(SocketAsyncEventArgs e)
    {
      // check if the remote host closed the connection
      AsyncUserToken token = (AsyncUserToken)e.UserToken;
      if (e.BytesTransferred > 0 && e.SocketError == SocketError.Success) {
        MemoryStream stream = new MemoryStream(e.Buffer);
        AnswerMessage(stream);
        e.SetBuffer(stream.ToArray(), 0, (int)stream.Position);
        bool willRaiseEvent = token.Socket.SendAsync(e);
        if (!willRaiseEvent) {
          ProcessSend(e);
        }
      } else {
        CloseClientSocket(e);
      }
    }

    /// <summary>
    /// This method is invoked when an asynchronous send operation completes.
    /// The method issues another receive on the socket to read any additional
    /// data sent from the client
    /// </summary>
    /// <param name="e"></param>
    private void ProcessSend(SocketAsyncEventArgs e)
    {
      if (e.SocketError == SocketError.Success) {
        CloseClientSocket(e);
      }
    }

    private void CloseClientSocket(SocketAsyncEventArgs e)
    {
      AsyncUserToken token = e.UserToken as AsyncUserToken;

      // close the socket associated with the client 
      try {
        token.Socket.Shutdown(SocketShutdown.Send);
        // throws if client process has already closed
      } catch (Exception) { }
      token.Socket.Close();

      this.maxNumberAcceptedClients.Release();

      // Free the SocketAsyncEventArg so they can be reused by another client
      this.socketAsyncEventArgsPool.Push(e);
    }

    public override void Dispose()
    {
      Dispose(true);
      GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
      this.isDisposed = true;

      Environment.SetEnvironmentVariable(LinAgent.SSH_AUTHSOCKET_ENV_NAME, null);
      Environment.SetEnvironmentVariable(LinAgent.SSH_AGENTPID_ENV_NAME, null);

      for (int i = 0; i < socketAsyncEventArgsPool.Count; i++) {

      }
      if (this.socket != null) {
        this.socket.Close();
      }
      if (this.socketDir != null && Directory.Exists(this.socketDir)) {
        Directory.Delete(this.socketDir, true);
      }
    }

    ~LinAgent()
    {
      Dispose(false);
    }
  }
}

