﻿//
// WinInternals.cs
//
// Copyright (c) 2015 David Lechner
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO.MemoryMappedFiles;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;

using BOOL = System.Boolean;
using BYTE = System.Byte;
using DWORD = System.UInt32;
using PVOID = System.IntPtr;
using ULONG = System.UInt32;
using USHORT = System.UInt16;

namespace dlech.SshAgentLib
{
    public static class WinInternals
    {
        const uint NO_ERROR = 0;
        const uint ERROR_NOT_SUPPORTED = 50;
        const uint ERROR_INVALID_PARAMETER = 87;
        const uint ERROR_INSUFFICIENT_BUFFER = 122;

        const uint AF_INET = 2;
        const uint AF_INET6 = 23;

        enum TCP_CONNECTION_OFFLOAD_STATE
        {
            TcpConnectionOffloadStateInHost = 0,
            TcpConnectionOffloadStateOffloading = 1,
            TcpConnectionOffloadStateOffloaded = 2,
            TcpConnectionOffloadStateUploading = 3,
            TcpConnectionOffloadStateMax = 4
        }

        enum MIB_TCP_STATE
        {
            MIB_TCP_STATE_CLOSED = 1,
            MIB_TCP_STATE_LISTEN = 2,
            MIB_TCP_STATE_SYN_SENT = 3,
            MIB_TCP_STATE_SYN_RCVD = 4,
            MIB_TCP_STATE_ESTAB = 5,
            MIB_TCP_STATE_FIN_WAIT1 = 6,
            MIB_TCP_STATE_FIN_WAIT2 = 7,
            MIB_TCP_STATE_CLOSE_WAIT = 8,
            MIB_TCP_STATE_CLOSING = 9,
            MIB_TCP_STATE_LAST_ACK = 10,
            MIB_TCP_STATE_TIME_WAIT = 11,
            MIB_TCP_STATE_DELETE_TCB = 12,
        }

        enum TCP_TABLE_CLASS
        {
            TCP_TABLE_BASIC_LISTENER,
            TCP_TABLE_BASIC_CONNECTIONS,
            TCP_TABLE_BASIC_ALL,
            TCP_TABLE_OWNER_PID_LISTENER,
            TCP_TABLE_OWNER_PID_CONNECTIONS,
            TCP_TABLE_OWNER_PID_ALL,
            TCP_TABLE_OWNER_MODULE_LISTENER,
            TCP_TABLE_OWNER_MODULE_CONNECTIONS,
            TCP_TABLE_OWNER_MODULE_ALL
        }

        // compiler complains about unused fields
#pragma warning disable 0649
        struct MIB_TCPROW_OWNER_PID
        {
            public MIB_TCP_STATE dwState;
            public DWORD dwLocalAddr;
            public DWORD dwLocalPort;
            public DWORD dwRemoteAddr;
            public DWORD dwRemotePort;
            public DWORD dwOwningPid;
        }
#pragma warning restore 0649

        [DllImport("Iphlpapi.dll")]
        static extern DWORD GetExtendedTcpTable(
            PVOID pTcpTable,
            ref DWORD pdwSize,
            BOOL bOrder,
            ULONG ulAf,
            TCP_TABLE_CLASS TableClass,
            ULONG Reserved = 0
        );

        /// <summary>
        /// Searches all current TCP connections (IPv4 only) for the matching
        /// port (local port of the connection).
        /// </summary>
        /// <param name="port">The TCP port to look for.</param>
        /// <returns>The process that owns this connection.</returns>
        public static Process GetProcessForTcpPort(
            IPEndPoint localEndpoint,
            IPEndPoint remoteEndpoint
        )
        {
            if (localEndpoint == null)
            {
                throw new ArgumentNullException("localEndpoint");
            }
            if (remoteEndpoint == null)
            {
                throw new ArgumentNullException("remoteEndpoint");
            }
            if (localEndpoint.AddressFamily != AddressFamily.InterNetwork)
            {
                throw new ArgumentException("Must be IPv4 address.", "localEndpoint");
            }
            if (remoteEndpoint.AddressFamily != AddressFamily.InterNetwork)
            {
                throw new ArgumentException("Must be IPv4 address.", "remoteEndpoint");
            }

            // The MIB_TCPROW_OWNER_PID struct stores address as integers in
            // network byte order, so we fixup the address to match.
            var localAddressBytes = localEndpoint.Address.GetAddressBytes();
            var localAddress =
                localAddressBytes[0]
                + (localAddressBytes[1] << 8)
                + (localAddressBytes[2] << 16)
                + (localAddressBytes[3] << 24);
            var remoteAddressBytes = localEndpoint.Address.GetAddressBytes();
            var remoteAddress =
                remoteAddressBytes[0]
                + (remoteAddressBytes[1] << 8)
                + (remoteAddressBytes[2] << 16)
                + (remoteAddressBytes[3] << 24);

            // The MIB_TCPROW_OWNER_PID struct stores ports in network byte
            // order, so we have to swap the port to match.
            var localPort = (ushort)IPAddress.HostToNetworkOrder((short)localEndpoint.Port);
            var remotePort = (ushort)IPAddress.HostToNetworkOrder((short)remoteEndpoint.Port);

            // first find out the size needed to get the data

            var buf = IntPtr.Zero;
            var bufSize = 0U;
            var result = GetExtendedTcpTable(
                buf,
                ref bufSize,
                false,
                AF_INET,
                TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_CONNECTIONS
            );
            if (result != ERROR_INSUFFICIENT_BUFFER)
            {
                throw new Exception(string.Format("Error: {0}", result));
            }

            // then alloc some memory so we can acutally get the data
            buf = Marshal.AllocHGlobal((int)bufSize);
            try
            {
                result = GetExtendedTcpTable(
                    buf,
                    ref bufSize,
                    false,
                    AF_INET,
                    TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_CONNECTIONS
                );
                if (result != NO_ERROR)
                {
                    throw new Exception(string.Format("Error: {0}", result));
                }
                var count = Marshal.ReadInt32(buf);
                var tablePtr = buf + sizeof(int);
                var rowSize = Marshal.SizeOf(typeof(MIB_TCPROW_OWNER_PID));
                var match = (MIB_TCPROW_OWNER_PID?)null;
                for (var i = 0; i < count; i++)
                {
                    var row = (MIB_TCPROW_OWNER_PID)
                        Marshal.PtrToStructure(tablePtr, typeof(MIB_TCPROW_OWNER_PID));
                    if (
                        localAddress == row.dwLocalAddr
                        && localPort == row.dwLocalPort
                        && remoteAddress == row.dwRemoteAddr
                        && remotePort == row.dwRemotePort
                    )
                    {
                        match = row;
                        break;
                    }
                    tablePtr += rowSize;
                }
                if (!match.HasValue)
                {
                    throw new Exception("Match not found.");
                }
                return Process.GetProcessById((int)match.Value.dwOwningPid);
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        struct SYSTEM_HANDLE_ENTRY
        {
            public ULONG OwnerPid;
            public BYTE ObjectType;
            public BYTE HandleFlags;
            public USHORT HandleValue;
            public PVOID ObjectPointer;
            public ULONG AccessMask;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct SYSTEM_HANDLE_INFORMATION
        {
            public ULONG Count;
            public IntPtr Handle; // array
        }

        [DllImport("ntdll.dll")]
        static extern NTSTATUS NtQuerySystemInformation(
            SYSTEM_INFORMATION_CLASS SystemInformationClass,
            PVOID SystemInformation,
            ULONG Length,
            out ULONG ResultLength
        );

        /// <summary>
        /// Iterates all open handles on the system (using internal system call)
        /// to find the other process that has a handle open to the same memtory
        /// mapped file.
        /// </summary>
        /// <remarks>
        /// Code based on http://forum.sysinternals.com/overview-handle-enumeration_topic14546.html
        /// </remarks>
        public static Process FindProcessWithMatchingHandle(MemoryMappedFile mmf)
        {
            // hopefully this is enough room (16MiB)
            const int sysInfoPtrLength = 4096 * 4096;
            var sysInfoPtr = Marshal.AllocHGlobal(sysInfoPtrLength);
            try
            {
                uint resultLength;
                var result = NtQuerySystemInformation(
                    SYSTEM_INFORMATION_CLASS.SystemHandleInformation,
                    sysInfoPtr,
                    sysInfoPtrLength,
                    out resultLength
                );
                if (result != 0)
                {
                    throw new Exception(result.ToString());
                }
                var info = (SYSTEM_HANDLE_INFORMATION)
                    Marshal.PtrToStructure(sysInfoPtr, typeof(SYSTEM_HANDLE_INFORMATION));

                // set entryPtr to position of info.Handle
                var entryPtr =
                    sysInfoPtr + Marshal.SizeOf(typeof(SYSTEM_HANDLE_INFORMATION)) - IntPtr.Size;
                var entries = new List<SYSTEM_HANDLE_ENTRY>();
                // we loop through a large number (10s of thousands) of handles,
                // so dereferencig everything first should improve perfomarnce
                var entryLength = Marshal.SizeOf(typeof(SYSTEM_HANDLE_ENTRY));
                var pid = Process.GetCurrentProcess().Id;
                var handle = (ushort)mmf.SafeMemoryMappedFileHandle.DangerousGetHandle();
                var match = IntPtr.Zero;
                for (var i = 0; i < info.Count; i++)
                {
                    var entry = (SYSTEM_HANDLE_ENTRY)
                        Marshal.PtrToStructure(entryPtr, typeof(SYSTEM_HANDLE_ENTRY));
                    // search for a handle for this process that matches the
                    // memory mapped file.
                    if (entry.OwnerPid == pid && entry.HandleValue == handle)
                    {
                        match = entry.ObjectPointer;
                    }
                    else
                    {
                        // Save all other entries excpt for the match to a list
                        // so we can search it again later
                        entries.Add(entry);
                    }
                    entryPtr += entryLength;
                }
                if (match == IntPtr.Zero)
                {
                    throw new Exception("Match not found.");
                }

                var otherHandle = entries.Single(e => e.ObjectPointer == match);
                return Process.GetProcessById((int)otherHandle.OwnerPid);
            }
            finally
            {
                Marshal.FreeHGlobal(sysInfoPtr);
            }
        }

        enum SYSTEM_INFORMATION_CLASS
        {
            SystemBasicInformation = 0,
            SystemCpuInformation = 1,
            SystemPerformanceInformation = 2,
            SystemTimeOfDayInformation = 3, /* was SystemTimeInformation */
            Unknown4,
            SystemProcessInformation = 5,
            Unknown6,
            Unknown7,
            SystemProcessorPerformanceInformation = 8,
            Unknown9,
            Unknown10,
            SystemModuleInformation = 11,
            Unknown12,
            Unknown13,
            Unknown14,
            Unknown15,
            SystemHandleInformation = 16,
            Unknown17,
            SystemPageFileInformation = 18,
            Unknown19,
            Unknown20,
            SystemCacheInformation = 21,
            Unknown22,
            SystemInterruptInformation = 23,
            SystemDpcBehaviourInformation = 24,
            SystemFullMemoryInformation = 25,
            SystemNotImplemented6 = 25,
            SystemLoadImage = 26,
            SystemUnloadImage = 27,
            SystemTimeAdjustmentInformation = 28,
            SystemTimeAdjustment = 28,
            SystemSummaryMemoryInformation = 29,
            SystemNotImplemented7 = 29,
            SystemNotImplemented8 = 30,
            SystemEventIdsInformation = 31,
            SystemCrashDumpInformation = 32,
            SystemExceptionInformation = 33,
            SystemCrashDumpStateInformation = 34,
            SystemKernelDebuggerInformation = 35,
            SystemContextSwitchInformation = 36,
            SystemRegistryQuotaInformation = 37,
            SystemCurrentTimeZoneInformation = 44,
            SystemTimeZoneInformation = 44,
            SystemLookasideInformation = 45,
            SystemSetTimeSlipEvent = 46,
            SystemCreateSession = 47,
            SystemDeleteSession = 48,
            SystemInvalidInfoClass4 = 49,
            SystemRangeStartInformation = 50,
            SystemVerifierInformation = 51,
            SystemAddVerifier = 52,
            SystemSessionProcessesInformation = 53,
            Unknown54,
            Unknown55,
            Unknown56,
            Unknown57,
            Unknown58,
            Unknown59,
            Unknown60,
            Unknown61,
            Unknown62,
            Unknown63,
            Unknown64,
            Unknown65,
            Unknown66,
            Unknown67,
            Unknown68,
            Unknown69,
            Unknown70,
            Unknown71,
            Unknown72,
            SystemLogicalProcessorInformation = 73,
            SystemInformationClassMax
        }

        enum NTSTATUS : uint
        {
            STATUS_SUCCESS = 0x00000000,
            STATUS_SEVERITY_SUCCESS = 0x00000000,
            STATUS_SEVERITY_INFORMATIONAL = 0x00000001,
            STATUS_SEVERITY_WARNING = 0x00000002,
            STATUS_SEVERITY_ERROR = 0x00000003,
            STATUS_WAIT_0 = 0x00000000,
            STATUS_WAIT_1 = 0x00000001,
            STATUS_WAIT_2 = 0x00000002,
            STATUS_WAIT_3 = 0x00000003,
            STATUS_WAIT_63 = 0x0000003f,
            STATUS_ABANDONED = 0x00000080,
            STATUS_ABANDONED_WAIT_0 = 0x00000080,
            STATUS_ABANDONED_WAIT_63 = 0x000000BF,
            STATUS_USER_APC = 0x000000C0,
            STATUS_KERNEL_APC = 0x00000100,
            STATUS_ALERTED = 0x00000101,
            STATUS_TIMEOUT = 0x00000102,
            STATUS_PENDING = 0x00000103,
            STATUS_REPARSE = 0x00000104,
            STATUS_MORE_ENTRIES = 0x00000105,
            STATUS_NOT_ALL_ASSIGNED = 0x00000106,
            STATUS_SOME_NOT_MAPPED = 0x00000107,
            STATUS_OPLOCK_BREAK_IN_PROGRESS = 0x00000108,
            STATUS_VOLUME_MOUNTED = 0x00000109,
            STATUS_RXACT_COMMITTED = 0x0000010A,
            STATUS_NOTIFY_CLEANUP = 0x0000010B,
            STATUS_NOTIFY_ENUM_DIR = 0x0000010C,
            STATUS_NO_QUOTAS_FOR_ACCOUNT = 0x0000010D,
            STATUS_PRIMARY_TRANSPORT_CONNECT_FAILED = 0x0000010E,
            STATUS_PAGE_FAULT_TRANSITION = 0x00000110,
            STATUS_PAGE_FAULT_DEMAND_ZERO = 0x00000111,
            STATUS_PAGE_FAULT_COPY_ON_WRITE = 0x00000112,
            STATUS_PAGE_FAULT_GUARD_PAGE = 0x00000113,
            STATUS_PAGE_FAULT_PAGING_FILE = 0x00000114,
            STATUS_CACHE_PAGE_LOCKED = 0x00000115,
            STATUS_CRASH_DUMP = 0x00000116,
            STATUS_BUFFER_ALL_ZEROS = 0x00000117,
            STATUS_REPARSE_OBJECT = 0x00000118,
            STATUS_RESOURCE_REQUIREMENTS_CHANGED = 0x00000119,
            STATUS_TRANSLATION_COMPLETE = 0x00000120,
            STATUS_DS_MEMBERSHIP_EVALUATED_LOCALLY = 0x00000121,
            STATUS_NOTHING_TO_TERMINATE = 0x00000122,
            STATUS_PROCESS_NOT_IN_JOB = 0x00000123,
            STATUS_PROCESS_IN_JOB = 0x00000124,
            STATUS_VOLSNAP_HIBERNATE_READY = 0x00000125,
            STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY = 0x00000126,
            STATUS_OBJECT_NAME_EXISTS = 0x40000000,
            STATUS_THREAD_WAS_SUSPENDED = 0x40000001,
            STATUS_WORKING_SET_LIMIT_RANGE = 0x40000002,
            STATUS_IMAGE_NOT_AT_BASE = 0x40000003,
            STATUS_RXACT_STATE_CREATED = 0x40000004,
            STATUS_SEGMENT_NOTIFICATION = 0x40000005,
            STATUS_LOCAL_USER_SESSION_KEY = 0x40000006,
            STATUS_BAD_CURRENT_DIRECTORY = 0x40000007,
            STATUS_SERIAL_MORE_WRITES = 0x40000008,
            STATUS_REGISTRY_RECOVERED = 0x40000009,
            STATUS_FT_READ_RECOVERY_FROM_BACKUP = 0x4000000A,
            STATUS_FT_WRITE_RECOVERY = 0x4000000B,
            STATUS_SERIAL_COUNTER_TIMEOUT = 0x4000000C,
            STATUS_NULL_LM_PASSWORD = 0x4000000D,
            STATUS_IMAGE_MACHINE_TYPE_MISMATCH = 0x4000000E,
            STATUS_RECEIVE_PARTIAL = 0x4000000F,
            STATUS_RECEIVE_EXPEDITED = 0x40000010,
            STATUS_RECEIVE_PARTIAL_EXPEDITED = 0x40000011,
            STATUS_EVENT_DONE = 0x40000012,
            STATUS_EVENT_PENDING = 0x40000013,
            STATUS_CHECKING_FILE_SYSTEM = 0x40000014,
            STATUS_FATAL_APP_EXIT = 0x40000015,
            STATUS_PREDEFINED_HANDLE = 0x40000016,
            STATUS_WAS_UNLOCKED = 0x40000017,
            STATUS_SERVICE_NOTIFICATION = 0x40000018,
            STATUS_WAS_LOCKED = 0x40000019,
            STATUS_LOG_HARD_ERROR = 0x4000001A,
            STATUS_ALREADY_WIN32 = 0x4000001B,
            STATUS_WX86_UNSIMULATE = 0x4000001C,
            STATUS_WX86_CONTINUE = 0x4000001D,
            STATUS_WX86_SINGLE_STEP = 0x4000001E,
            STATUS_WX86_BREAKPOINT = 0x4000001F,
            STATUS_WX86_EXCEPTION_CONTINUE = 0x40000020,
            STATUS_WX86_EXCEPTION_LASTCHANCE = 0x40000021,
            STATUS_WX86_EXCEPTION_CHAIN = 0x40000022,
            STATUS_IMAGE_MACHINE_TYPE_MISMATCH_EXE = 0x40000023,
            STATUS_NO_YIELD_PERFORMED = 0x40000024,
            STATUS_TIMER_RESUME_IGNORED = 0x40000025,
            STATUS_ARBITRATION_UNHANDLED = 0x40000026,
            STATUS_CARDBUS_NOT_SUPPORTED = 0x40000027,
            STATUS_WX86_CREATEWX86TIB = 0x40000028,
            STATUS_MP_PROCESSOR_MISMATCH = 0x40000029,
            STATUS_HIBERNATED = 0x4000002A,
            STATUS_RESUME_HIBERNATION = 0x4000002B,
            STATUS_FIRMWARE_UPDATED = 0x4000002C,
            STATUS_WAKE_SYSTEM = 0x40000294,
            STATUS_DS_SHUTTING_DOWN = 0x40000370,
            RPC_NT_UUID_LOCAL_ONLY = 0x40020056,
            RPC_NT_SEND_INCOMPLETE = 0x400200AF,
            STATUS_CTX_CDM_CONNECT = 0x400A0004,
            STATUS_CTX_CDM_DISCONNECT = 0x400A0005,
            STATUS_SXS_RELEASE_ACTIVATION_CONTEXT = 0x4015000D,
            STATUS_GUARD_PAGE_VIOLATION = 0x80000001,
            STATUS_DATATYPE_MISALIGNMENT = 0x80000002,
            STATUS_BREAKPOINT = 0x80000003,
            STATUS_SINGLE_STEP = 0x80000004,
            STATUS_BUFFER_OVERFLOW = 0x80000005,
            STATUS_NO_MORE_FILES = 0x80000006,
            STATUS_WAKE_SYSTEM_DEBUGGER = 0x80000007,
            STATUS_HANDLES_CLOSED = 0x8000000A,
            STATUS_NO_INHERITANCE = 0x8000000B,
            STATUS_GUID_SUBSTITUTION_MADE = 0x8000000C,
            STATUS_PARTIAL_COPY = 0x8000000D,
            STATUS_DEVICE_PAPER_EMPTY = 0x8000000E,
            STATUS_DEVICE_POWERED_OFF = 0x8000000F,
            STATUS_DEVICE_OFF_LINE = 0x80000010,
            STATUS_DEVICE_BUSY = 0x80000011,
            STATUS_NO_MORE_EAS = 0x80000012,
            STATUS_INVALID_EA_NAME = 0x80000013,
            STATUS_EA_LIST_INCONSISTENT = 0x80000014,
            STATUS_INVALID_EA_FLAG = 0x80000015,
            STATUS_VERIFY_REQUIRED = 0x80000016,
            STATUS_EXTRANEOUS_INFORMATION = 0x80000017,
            STATUS_RXACT_COMMIT_NECESSARY = 0x80000018,
            STATUS_NO_MORE_ENTRIES = 0x8000001A,
            STATUS_FILEMARK_DETECTED = 0x8000001B,
            STATUS_MEDIA_CHANGED = 0x8000001C,
            STATUS_BUS_RESET = 0x8000001D,
            STATUS_END_OF_MEDIA = 0x8000001E,
            STATUS_BEGINNING_OF_MEDIA = 0x8000001F,
            STATUS_MEDIA_CHECK = 0x80000020,
            STATUS_SETMARK_DETECTED = 0x80000021,
            STATUS_NO_DATA_DETECTED = 0x80000022,
            STATUS_REDIRECTOR_HAS_OPEN_HANDLES = 0x80000023,
            STATUS_SERVER_HAS_OPEN_HANDLES = 0x80000024,
            STATUS_ALREADY_DISCONNECTED = 0x80000025,
            STATUS_LONGJUMP = 0x80000026,
            STATUS_CLEANER_CARTRIDGE_INSTALLED = 0x80000027,
            STATUS_PLUGPLAY_QUERY_VETOED = 0x80000028,
            STATUS_UNWIND_CONSOLIDATE = 0x80000029,
            STATUS_REGISTRY_HIVE_RECOVERED = 0x8000002A,
            STATUS_DLL_MIGHT_BE_INSECURE = 0x8000002B,
            STATUS_DLL_MIGHT_BE_INCOMPATIBLE = 0x8000002C,
            STATUS_DEVICE_REQUIRES_CLEANING = 0x80000288,
            STATUS_DEVICE_DOOR_OPEN = 0x80000289,
            STATUS_CLUSTER_NODE_ALREADY_UP = 0x80130001,
            STATUS_CLUSTER_NODE_ALREADY_DOWN = 0x80130002,
            STATUS_CLUSTER_NETWORK_ALREADY_ONLINE = 0x80130003,
            STATUS_CLUSTER_NETWORK_ALREADY_OFFLINE = 0x80130004,
            STATUS_CLUSTER_NODE_ALREADY_MEMBER = 0x80130005,
            STATUS_UNSUCCESSFUL = 0xC0000001,
            STATUS_NOT_IMPLEMENTED = 0xC0000002,
            STATUS_INVALID_INFO_CLASS = 0xC0000003,
            STATUS_INFO_LENGTH_MISMATCH = 0xC0000004,
            STATUS_ACCESS_VIOLATION = 0xC0000005,
            STATUS_IN_PAGE_ERROR = 0xC0000006,
            STATUS_PAGEFILE_QUOTA = 0xC0000007,
            STATUS_INVALID_HANDLE = 0xC0000008,
            STATUS_BAD_INITIAL_STACK = 0xC0000009,
            STATUS_BAD_INITIAL_PC = 0xC000000A,
            STATUS_INVALID_CID = 0xC000000B,
            STATUS_TIMER_NOT_CANCELED = 0xC000000C,
            STATUS_INVALID_PARAMETER = 0xC000000D,
            STATUS_NO_SUCH_DEVICE = 0xC000000E,
            STATUS_NO_SUCH_FILE = 0xC000000F,
            STATUS_INVALID_DEVICE_REQUEST = 0xC0000010,
            STATUS_END_OF_FILE = 0xC0000011,
            STATUS_WRONG_VOLUME = 0xC0000012,
            STATUS_NO_MEDIA_IN_DEVICE = 0xC0000013,
            STATUS_UNRECOGNIZED_MEDIA = 0xC0000014,
            STATUS_NONEXISTENT_SECTOR = 0xC0000015,
            STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016,
            STATUS_NO_MEMORY = 0xC0000017,
            STATUS_CONFLICTING_ADDRESSES = 0xC0000018,
            STATUS_NOT_MAPPED_VIEW = 0xC0000019,
            STATUS_UNABLE_TO_FREE_VM = 0xC000001A,
            STATUS_UNABLE_TO_DELETE_SECTION = 0xC000001B,
            STATUS_INVALID_SYSTEM_SERVICE = 0xC000001C,
            STATUS_ILLEGAL_INSTRUCTION = 0xC000001D,
            STATUS_INVALID_LOCK_SEQUENCE = 0xC000001E,
            STATUS_INVALID_VIEW_SIZE = 0xC000001F,
            STATUS_INVALID_FILE_FOR_SECTION = 0xC0000020,
            STATUS_ALREADY_COMMITTED = 0xC0000021,
            STATUS_ACCESS_DENIED = 0xC0000022,
            STATUS_BUFFER_TOO_SMALL = 0xC0000023,
            STATUS_OBJECT_TYPE_MISMATCH = 0xC0000024,
            STATUS_NONCONTINUABLE_EXCEPTION = 0xC0000025,
            STATUS_INVALID_DISPOSITION = 0xC0000026,
            STATUS_UNWIND = 0xC0000027,
            STATUS_BAD_STACK = 0xC0000028,
            STATUS_INVALID_UNWIND_TARGET = 0xC0000029,
            STATUS_NOT_LOCKED = 0xC000002A,
            STATUS_PARITY_ERROR = 0xC000002B,
            STATUS_UNABLE_TO_DECOMMIT_VM = 0xC000002C,
            STATUS_NOT_COMMITTED = 0xC000002D,
            STATUS_INVALID_PORT_ATTRIBUTES = 0xC000002E,
            STATUS_PORT_MESSAGE_TOO_LONG = 0xC000002F,
            STATUS_INVALID_PARAMETER_MIX = 0xC0000030,
            STATUS_INVALID_QUOTA_LOWER = 0xC0000031,
            STATUS_DISK_CORRUPT_ERROR = 0xC0000032,
            STATUS_OBJECT_NAME_INVALID = 0xC0000033,
            STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034,
            STATUS_OBJECT_NAME_COLLISION = 0xC0000035,
            STATUS_PORT_DISCONNECTED = 0xC0000037,
            STATUS_DEVICE_ALREADY_ATTACHED = 0xC0000038,
            STATUS_OBJECT_PATH_INVALID = 0xC0000039,
            STATUS_OBJECT_PATH_NOT_FOUND = 0xC000003A,
            STATUS_OBJECT_PATH_SYNTAX_BAD = 0xC000003B,
            STATUS_DATA_OVERRUN = 0xC000003C,
            STATUS_DATA_LATE_ERROR = 0xC000003D,
            STATUS_DATA_ERROR = 0xC000003E,
            STATUS_CRC_ERROR = 0xC000003F,
            STATUS_SECTION_TOO_BIG = 0xC0000040,
            STATUS_PORT_CONNECTION_REFUSED = 0xC0000041,
            STATUS_INVALID_PORT_HANDLE = 0xC0000042,
            STATUS_SHARING_VIOLATION = 0xC0000043,
            STATUS_QUOTA_EXCEEDED = 0xC0000044,
            STATUS_INVALID_PAGE_PROTECTION = 0xC0000045,
            STATUS_MUTANT_NOT_OWNED = 0xC0000046,
            STATUS_SEMAPHORE_LIMIT_EXCEEDED = 0xC0000047,
            STATUS_PORT_ALREADY_SET = 0xC0000048,
            STATUS_SECTION_NOT_IMAGE = 0xC0000049,
            STATUS_SUSPEND_COUNT_EXCEEDED = 0xC000004A,
            STATUS_THREAD_IS_TERMINATING = 0xC000004B,
            STATUS_BAD_WORKING_SET_LIMIT = 0xC000004C,
            STATUS_INCOMPATIBLE_FILE_MAP = 0xC000004D,
            STATUS_SECTION_PROTECTION = 0xC000004E,
            STATUS_EAS_NOT_SUPPORTED = 0xC000004F,
            STATUS_EA_TOO_LARGE = 0xC0000050,
            STATUS_NONEXISTENT_EA_ENTRY = 0xC0000051,
            STATUS_NO_EAS_ON_FILE = 0xC0000052,
            STATUS_EA_CORRUPT_ERROR = 0xC0000053,
            STATUS_FILE_LOCK_CONFLICT = 0xC0000054,
            STATUS_LOCK_NOT_GRANTED = 0xC0000055,
            STATUS_DELETE_PENDING = 0xC0000056,
            STATUS_CTL_FILE_NOT_SUPPORTED = 0xC0000057,
            STATUS_UNKNOWN_REVISION = 0xC0000058,
            STATUS_REVISION_MISMATCH = 0xC0000059,
            STATUS_INVALID_OWNER = 0xC000005A,
            STATUS_INVALID_PRIMARY_GROUP = 0xC000005B,
            STATUS_NO_IMPERSONATION_TOKEN = 0xC000005C,
            STATUS_CANT_DISABLE_MANDATORY = 0xC000005D,
            STATUS_NO_LOGON_SERVERS = 0xC000005E,
            STATUS_NO_SUCH_LOGON_SESSION = 0xC000005F,
            STATUS_NO_SUCH_PRIVILEGE = 0xC0000060,
            STATUS_PRIVILEGE_NOT_HELD = 0xC0000061,
            STATUS_INVALID_ACCOUNT_NAME = 0xC0000062,
            STATUS_USER_EXISTS = 0xC0000063,
            STATUS_NO_SUCH_USER = 0xC0000064,
            STATUS_GROUP_EXISTS = 0xC0000065,
            STATUS_NO_SUCH_GROUP = 0xC0000066,
            STATUS_MEMBER_IN_GROUP = 0xC0000067,
            STATUS_MEMBER_NOT_IN_GROUP = 0xC0000068,
            STATUS_LAST_ADMIN = 0xC0000069,
            STATUS_WRONG_PASSWORD = 0xC000006A,
            STATUS_ILL_FORMED_PASSWORD = 0xC000006B,
            STATUS_PASSWORD_RESTRICTION = 0xC000006C,
            STATUS_LOGON_FAILURE = 0xC000006D,
            STATUS_ACCOUNT_RESTRICTION = 0xC000006E,
            STATUS_INVALID_LOGON_HOURS = 0xC000006F,
            STATUS_INVALID_WORKSTATION = 0xC0000070,
            STATUS_PASSWORD_EXPIRED = 0xC0000071,
            STATUS_ACCOUNT_DISABLED = 0xC0000072,
            STATUS_NONE_MAPPED = 0xC0000073,
            STATUS_TOO_MANY_LUIDS_REQUESTED = 0xC0000074,
            STATUS_LUIDS_EXHAUSTED = 0xC0000075,
            STATUS_INVALID_SUB_AUTHORITY = 0xC0000076,
            STATUS_INVALID_ACL = 0xC0000077,
            STATUS_INVALID_SID = 0xC0000078,
            STATUS_INVALID_SECURITY_DESCR = 0xC0000079,
            STATUS_PROCEDURE_NOT_FOUND = 0xC000007A,
            STATUS_INVALID_IMAGE_FORMAT = 0xC000007B,
            STATUS_NO_TOKEN = 0xC000007C,
            STATUS_BAD_INHERITANCE_ACL = 0xC000007D,
            STATUS_RANGE_NOT_LOCKED = 0xC000007E,
            STATUS_DISK_FULL = 0xC000007F,
            STATUS_SERVER_DISABLED = 0xC0000080,
            STATUS_SERVER_NOT_DISABLED = 0xC0000081,
            STATUS_TOO_MANY_GUIDS_REQUESTED = 0xC0000082,
            STATUS_GUIDS_EXHAUSTED = 0xC0000083,
            STATUS_INVALID_ID_AUTHORITY = 0xC0000084,
            STATUS_AGENTS_EXHAUSTED = 0xC0000085,
            STATUS_INVALID_VOLUME_LABEL = 0xC0000086,
            STATUS_SECTION_NOT_EXTENDED = 0xC0000087,
            STATUS_NOT_MAPPED_DATA = 0xC0000088,
            STATUS_RESOURCE_DATA_NOT_FOUND = 0xC0000089,
            STATUS_RESOURCE_TYPE_NOT_FOUND = 0xC000008A,
            STATUS_RESOURCE_NAME_NOT_FOUND = 0xC000008B,
            STATUS_ARRAY_BOUNDS_EXCEEDED = 0xC000008C,
            STATUS_FLOAT_DENORMAL_OPERAND = 0xC000008D,
            STATUS_FLOAT_DIVIDE_BY_ZERO = 0xC000008E,
            STATUS_FLOAT_INEXACT_RESULT = 0xC000008F,
            STATUS_FLOAT_INVALID_OPERATION = 0xC0000090,
            STATUS_FLOAT_OVERFLOW = 0xC0000091,
            STATUS_FLOAT_STACK_CHECK = 0xC0000092,
            STATUS_FLOAT_UNDERFLOW = 0xC0000093,
            STATUS_INTEGER_DIVIDE_BY_ZERO = 0xC0000094,
            STATUS_INTEGER_OVERFLOW = 0xC0000095,
            STATUS_PRIVILEGED_INSTRUCTION = 0xC0000096,
            STATUS_TOO_MANY_PAGING_FILES = 0xC0000097,
            STATUS_FILE_INVALID = 0xC0000098,
            STATUS_ALLOTTED_SPACE_EXCEEDED = 0xC0000099,
            STATUS_INSUFFICIENT_RESOURCES = 0xC000009A,
            STATUS_DFS_EXIT_PATH_FOUND = 0xC000009B,
            STATUS_DEVICE_DATA_ERROR = 0xC000009C,
            STATUS_DEVICE_NOT_CONNECTED = 0xC000009D,
            STATUS_DEVICE_POWER_FAILURE = 0xC000009E,
            STATUS_FREE_VM_NOT_AT_BASE = 0xC000009F,
            STATUS_MEMORY_NOT_ALLOCATED = 0xC00000A0,
            STATUS_WORKING_SET_QUOTA = 0xC00000A1,
            STATUS_MEDIA_WRITE_PROTECTED = 0xC00000A2,
            STATUS_DEVICE_NOT_READY = 0xC00000A3,
            STATUS_INVALID_GROUP_ATTRIBUTES = 0xC00000A4,
            STATUS_BAD_IMPERSONATION_LEVEL = 0xC00000A5,
            STATUS_CANT_OPEN_ANONYMOUS = 0xC00000A6,
            STATUS_BAD_VALIDATION_CLASS = 0xC00000A7,
            STATUS_BAD_TOKEN_TYPE = 0xC00000A8,
            STATUS_BAD_MASTER_BOOT_RECORD = 0xC00000A9,
            STATUS_INSTRUCTION_MISALIGNMENT = 0xC00000AA,
            STATUS_INSTANCE_NOT_AVAILABLE = 0xC00000AB,
            STATUS_PIPE_NOT_AVAILABLE = 0xC00000AC,
            STATUS_INVALID_PIPE_STATE = 0xC00000AD,
            STATUS_PIPE_BUSY = 0xC00000AE,
            STATUS_ILLEGAL_FUNCTION = 0xC00000AF,
            STATUS_PIPE_DISCONNECTED = 0xC00000B0,
            STATUS_PIPE_CLOSING = 0xC00000B1,
            STATUS_PIPE_CONNECTED = 0xC00000B2,
            STATUS_PIPE_LISTENING = 0xC00000B3,
            STATUS_INVALID_READ_MODE = 0xC00000B4,
            STATUS_IO_TIMEOUT = 0xC00000B5,
            STATUS_FILE_FORCED_CLOSED = 0xC00000B6,
            STATUS_PROFILING_NOT_STARTED = 0xC00000B7,
            STATUS_PROFILING_NOT_STOPPED = 0xC00000B8,
            STATUS_COULD_NOT_INTERPRET = 0xC00000B9,
            STATUS_FILE_IS_A_DIRECTORY = 0xC00000BA,
            STATUS_NOT_SUPPORTED = 0xC00000BB,
            STATUS_REMOTE_NOT_LISTENING = 0xC00000BC,
            STATUS_DUPLICATE_NAME = 0xC00000BD,
            STATUS_BAD_NETWORK_PATH = 0xC00000BE,
            STATUS_NETWORK_BUSY = 0xC00000BF,
            STATUS_DEVICE_DOES_NOT_EXIST = 0xC00000C0,
            STATUS_TOO_MANY_COMMANDS = 0xC00000C1,
            STATUS_ADAPTER_HARDWARE_ERROR = 0xC00000C2,
            STATUS_INVALID_NETWORK_RESPONSE = 0xC00000C3,
            STATUS_UNEXPECTED_NETWORK_ERROR = 0xC00000C4,
            STATUS_BAD_REMOTE_ADAPTER = 0xC00000C5,
            STATUS_PRINT_QUEUE_FULL = 0xC00000C6,
            STATUS_NO_SPOOL_SPACE = 0xC00000C7,
            STATUS_PRINT_CANCELLED = 0xC00000C8,
            STATUS_NETWORK_NAME_DELETED = 0xC00000C9,
            STATUS_NETWORK_ACCESS_DENIED = 0xC00000CA,
            STATUS_BAD_DEVICE_TYPE = 0xC00000CB,
            STATUS_BAD_NETWORK_NAME = 0xC00000CC,
            STATUS_TOO_MANY_NAMES = 0xC00000CD,
            STATUS_TOO_MANY_SESSIONS = 0xC00000CE,
            STATUS_SHARING_PAUSED = 0xC00000CF,
            STATUS_REQUEST_NOT_ACCEPTED = 0xC00000D0,
            STATUS_REDIRECTOR_PAUSED = 0xC00000D1,
            STATUS_NET_WRITE_FAULT = 0xC00000D2,
            STATUS_PROFILING_AT_LIMIT = 0xC00000D3,
            STATUS_NOT_SAME_DEVICE = 0xC00000D4,
            STATUS_FILE_RENAMED = 0xC00000D5,
            STATUS_VIRTUAL_CIRCUIT_CLOSED = 0xC00000D6,
            STATUS_NO_SECURITY_ON_OBJECT = 0xC00000D7,
            STATUS_CANT_WAIT = 0xC00000D8,
            STATUS_PIPE_EMPTY = 0xC00000D9,
            STATUS_CANT_ACCESS_DOMAIN_INFO = 0xC00000DA,
            STATUS_CANT_TERMINATE_SELF = 0xC00000DB,
            STATUS_INVALID_SERVER_STATE = 0xC00000DC,
            STATUS_INVALID_DOMAIN_STATE = 0xC00000DD,
            STATUS_INVALID_DOMAIN_ROLE = 0xC00000DE,
            STATUS_NO_SUCH_DOMAIN = 0xC00000DF,
            STATUS_DOMAIN_EXISTS = 0xC00000E0,
            STATUS_DOMAIN_LIMIT_EXCEEDED = 0xC00000E1,
            STATUS_OPLOCK_NOT_GRANTED = 0xC00000E2,
            STATUS_INVALID_OPLOCK_PROTOCOL = 0xC00000E3,
            STATUS_INTERNAL_DB_CORRUPTION = 0xC00000E4,
            STATUS_INTERNAL_ERROR = 0xC00000E5,
            STATUS_GENERIC_NOT_MAPPED = 0xC00000E6,
            STATUS_BAD_DESCRIPTOR_FORMAT = 0xC00000E7,
            STATUS_INVALID_USER_BUFFER = 0xC00000E8,
            STATUS_UNEXPECTED_IO_ERROR = 0xC00000E9,
            STATUS_UNEXPECTED_MM_CREATE_ERR = 0xC00000EA,
            STATUS_UNEXPECTED_MM_MAP_ERROR = 0xC00000EB,
            STATUS_UNEXPECTED_MM_EXTEND_ERR = 0xC00000EC,
            STATUS_NOT_LOGON_PROCESS = 0xC00000ED,
            STATUS_LOGON_SESSION_EXISTS = 0xC00000EE,
            STATUS_INVALID_PARAMETER_1 = 0xC00000EF,
            STATUS_INVALID_PARAMETER_2 = 0xC00000F0,
            STATUS_INVALID_PARAMETER_3 = 0xC00000F1,
            STATUS_INVALID_PARAMETER_4 = 0xC00000F2,
            STATUS_INVALID_PARAMETER_5 = 0xC00000F3,
            STATUS_INVALID_PARAMETER_6 = 0xC00000F4,
            STATUS_INVALID_PARAMETER_7 = 0xC00000F5,
            STATUS_INVALID_PARAMETER_8 = 0xC00000F6,
            STATUS_INVALID_PARAMETER_9 = 0xC00000F7,
            STATUS_INVALID_PARAMETER_10 = 0xC00000F8,
            STATUS_INVALID_PARAMETER_11 = 0xC00000F9,
            STATUS_INVALID_PARAMETER_12 = 0xC00000FA,
            STATUS_REDIRECTOR_NOT_STARTED = 0xC00000FB,
            STATUS_REDIRECTOR_STARTED = 0xC00000FC,
            STATUS_STACK_OVERFLOW = 0xC00000FD,
            STATUS_NO_SUCH_PACKAGE = 0xC00000FE,
            STATUS_BAD_FUNCTION_TABLE = 0xC00000FF,
            STATUS_VARIABLE_NOT_FOUND = 0xC0000100,
            STATUS_DIRECTORY_NOT_EMPTY = 0xC0000101,
            STATUS_FILE_CORRUPT_ERROR = 0xC0000102,
            STATUS_NOT_A_DIRECTORY = 0xC0000103,
            STATUS_BAD_LOGON_SESSION_STATE = 0xC0000104,
            STATUS_LOGON_SESSION_COLLISION = 0xC0000105,
            STATUS_NAME_TOO_LONG = 0xC0000106,
            STATUS_FILES_OPEN = 0xC0000107,
            STATUS_CONNECTION_IN_USE = 0xC0000108,
            STATUS_MESSAGE_NOT_FOUND = 0xC0000109,
            STATUS_PROCESS_IS_TERMINATING = 0xC000010A,
            STATUS_INVALID_LOGON_TYPE = 0xC000010B,
            STATUS_NO_GUID_TRANSLATION = 0xC000010C,
            STATUS_CANNOT_IMPERSONATE = 0xC000010D,
            STATUS_IMAGE_ALREADY_LOADED = 0xC000010E,
            STATUS_ABIOS_NOT_PRESENT = 0xC000010F,
            STATUS_ABIOS_LID_NOT_EXIST = 0xC0000110,
            STATUS_ABIOS_LID_ALREADY_OWNED = 0xC0000111,
            STATUS_ABIOS_NOT_LID_OWNER = 0xC0000112,
            STATUS_ABIOS_INVALID_COMMAND = 0xC0000113,
            STATUS_ABIOS_INVALID_LID = 0xC0000114,
            STATUS_ABIOS_SELECTOR_NOT_AVAILABLE = 0xC0000115,
            STATUS_ABIOS_INVALID_SELECTOR = 0xC0000116,
            STATUS_NO_LDT = 0xC0000117,
            STATUS_INVALID_LDT_SIZE = 0xC0000118,
            STATUS_INVALID_LDT_OFFSET = 0xC0000119,
            STATUS_INVALID_LDT_DESCRIPTOR = 0xC000011A,
            STATUS_INVALID_IMAGE_NE_FORMAT = 0xC000011B,
            STATUS_RXACT_INVALID_STATE = 0xC000011C,
            STATUS_RXACT_COMMIT_FAILURE = 0xC000011D,
            STATUS_MAPPED_FILE_SIZE_ZERO = 0xC000011E,
            STATUS_TOO_MANY_OPENED_FILES = 0xC000011F,
            STATUS_CANCELLED = 0xC0000120,
            STATUS_CANNOT_DELETE = 0xC0000121,
            STATUS_INVALID_COMPUTER_NAME = 0xC0000122,
            STATUS_FILE_DELETED = 0xC0000123,
            STATUS_SPECIAL_ACCOUNT = 0xC0000124,
            STATUS_SPECIAL_GROUP = 0xC0000125,
            STATUS_SPECIAL_USER = 0xC0000126,
            STATUS_MEMBERS_PRIMARY_GROUP = 0xC0000127,
            STATUS_FILE_CLOSED = 0xC0000128,
            STATUS_TOO_MANY_THREADS = 0xC0000129,
            STATUS_THREAD_NOT_IN_PROCESS = 0xC000012A,
            STATUS_TOKEN_ALREADY_IN_USE = 0xC000012B,
            STATUS_PAGEFILE_QUOTA_EXCEEDED = 0xC000012C,
            STATUS_COMMITMENT_LIMIT = 0xC000012D,
            STATUS_INVALID_IMAGE_LE_FORMAT = 0xC000012E,
            STATUS_INVALID_IMAGE_NOT_MZ = 0xC000012F,
            STATUS_INVALID_IMAGE_PROTECT = 0xC0000130,
            STATUS_INVALID_IMAGE_WIN_16 = 0xC0000131,
            STATUS_LOGON_SERVER_CONFLICT = 0xC0000132,
            STATUS_TIME_DIFFERENCE_AT_DC = 0xC0000133,
            STATUS_SYNCHRONIZATION_REQUIRED = 0xC0000134,
            STATUS_DLL_NOT_FOUND = 0xC0000135,
            STATUS_OPEN_FAILED = 0xC0000136,
            STATUS_IO_PRIVILEGE_FAILED = 0xC0000137,
            STATUS_ORDINAL_NOT_FOUND = 0xC0000138,
            STATUS_ENTRYPOINT_NOT_FOUND = 0xC0000139,
            STATUS_CONTROL_C_EXIT = 0xC000013A,
            STATUS_LOCAL_DISCONNECT = 0xC000013B,
            STATUS_REMOTE_DISCONNECT = 0xC000013C,
            STATUS_REMOTE_RESOURCES = 0xC000013D,
            STATUS_LINK_FAILED = 0xC000013E,
            STATUS_LINK_TIMEOUT = 0xC000013F,
            STATUS_INVALID_CONNECTION = 0xC0000140,
            STATUS_INVALID_ADDRESS = 0xC0000141,
            STATUS_DLL_INIT_FAILED = 0xC0000142,
            STATUS_MISSING_SYSTEMFILE = 0xC0000143,
            STATUS_UNHANDLED_EXCEPTION = 0xC0000144,
            STATUS_APP_INIT_FAILURE = 0xC0000145,
            STATUS_PAGEFILE_CREATE_FAILED = 0xC0000146,
            STATUS_NO_PAGEFILE = 0xC0000147,
            STATUS_INVALID_LEVEL = 0xC0000148,
            STATUS_WRONG_PASSWORD_CORE = 0xC0000149,
            STATUS_ILLEGAL_FLOAT_CONTEXT = 0xC000014A,
            STATUS_PIPE_BROKEN = 0xC000014B,
            STATUS_REGISTRY_CORRUPT = 0xC000014C,
            STATUS_REGISTRY_IO_FAILED = 0xC000014D,
            STATUS_NO_EVENT_PAIR = 0xC000014E,
            STATUS_UNRECOGNIZED_VOLUME = 0xC000014F,
            STATUS_SERIAL_NO_DEVICE_INITED = 0xC0000150,
            STATUS_NO_SUCH_ALIAS = 0xC0000151,
            STATUS_MEMBER_NOT_IN_ALIAS = 0xC0000152,
            STATUS_MEMBER_IN_ALIAS = 0xC0000153,
            STATUS_ALIAS_EXISTS = 0xC0000154,
            STATUS_LOGON_NOT_GRANTED = 0xC0000155,
            STATUS_TOO_MANY_SECRETS = 0xC0000156,
            STATUS_SECRET_TOO_LONG = 0xC0000157,
            STATUS_INTERNAL_DB_ERROR = 0xC0000158,
            STATUS_FULLSCREEN_MODE = 0xC0000159,
            STATUS_TOO_MANY_CONTEXT_IDS = 0xC000015A,
            STATUS_LOGON_TYPE_NOT_GRANTED = 0xC000015B,
            STATUS_NOT_REGISTRY_FILE = 0xC000015C,
            STATUS_NT_CROSS_ENCRYPTION_REQUIRED = 0xC000015D,
            STATUS_DOMAIN_CTRLR_CONFIG_ERROR = 0xC000015E,
            STATUS_FT_MISSING_MEMBER = 0xC000015F,
            STATUS_ILL_FORMED_SERVICE_ENTRY = 0xC0000160,
            STATUS_ILLEGAL_CHARACTER = 0xC0000161,
            STATUS_UNMAPPABLE_CHARACTER = 0xC0000162,
            STATUS_UNDEFINED_CHARACTER = 0xC0000163,
            STATUS_FLOPPY_VOLUME = 0xC0000164,
            STATUS_FLOPPY_ID_MARK_NOT_FOUND = 0xC0000165,
            STATUS_FLOPPY_WRONG_CYLINDER = 0xC0000166,
            STATUS_FLOPPY_UNKNOWN_ERROR = 0xC0000167,
            STATUS_FLOPPY_BAD_REGISTERS = 0xC0000168,
            STATUS_DISK_RECALIBRATE_FAILED = 0xC0000169,
            STATUS_DISK_OPERATION_FAILED = 0xC000016A,
            STATUS_DISK_RESET_FAILED = 0xC000016B,
            STATUS_SHARED_IRQ_BUSY = 0xC000016C,
            STATUS_FT_ORPHANING = 0xC000016D,
            STATUS_BIOS_FAILED_TO_CONNECT_INTERRUPT = 0xC000016E,
            STATUS_PARTITION_FAILURE = 0xC0000172,
            STATUS_INVALID_BLOCK_LENGTH = 0xC0000173,
            STATUS_DEVICE_NOT_PARTITIONED = 0xC0000174,
            STATUS_UNABLE_TO_LOCK_MEDIA = 0xC0000175,
            STATUS_UNABLE_TO_UNLOAD_MEDIA = 0xC0000176,
            STATUS_EOM_OVERFLOW = 0xC0000177,
            STATUS_NO_MEDIA = 0xC0000178,
            STATUS_NO_SUCH_MEMBER = 0xC000017A,
            STATUS_INVALID_MEMBER = 0xC000017B,
            STATUS_KEY_DELETED = 0xC000017C,
            STATUS_NO_LOG_SPACE = 0xC000017D,
            STATUS_TOO_MANY_SIDS = 0xC000017E,
            STATUS_LM_CROSS_ENCRYPTION_REQUIRED = 0xC000017F,
            STATUS_KEY_HAS_CHILDREN = 0xC0000180,
            STATUS_CHILD_MUST_BE_VOLATILE = 0xC0000181,
            STATUS_DEVICE_CONFIGURATION_ERROR = 0xC0000182,
            STATUS_DRIVER_INTERNAL_ERROR = 0xC0000183,
            STATUS_INVALID_DEVICE_STATE = 0xC0000184,
            STATUS_IO_DEVICE_ERROR = 0xC0000185,
            STATUS_DEVICE_PROTOCOL_ERROR = 0xC0000186,
            STATUS_BACKUP_CONTROLLER = 0xC0000187,
            STATUS_LOG_FILE_FULL = 0xC0000188,
            STATUS_TOO_LATE = 0xC0000189,
            STATUS_NO_TRUST_LSA_SECRET = 0xC000018A,
            STATUS_NO_TRUST_SAM_ACCOUNT = 0xC000018B,
            STATUS_TRUSTED_DOMAIN_FAILURE = 0xC000018C,
            STATUS_TRUSTED_RELATIONSHIP_FAILURE = 0xC000018D,
            STATUS_EVENTLOG_FILE_CORRUPT = 0xC000018E,
            STATUS_EVENTLOG_CANT_START = 0xC000018F,
            STATUS_TRUST_FAILURE = 0xC0000190,
            STATUS_MUTANT_LIMIT_EXCEEDED = 0xC0000191,
            STATUS_NETLOGON_NOT_STARTED = 0xC0000192,
            STATUS_ACCOUNT_EXPIRED = 0xC0000193,
            STATUS_POSSIBLE_DEADLOCK = 0xC0000194,
            STATUS_NETWORK_CREDENTIAL_CONFLICT = 0xC0000195,
            STATUS_REMOTE_SESSION_LIMIT = 0xC0000196,
            STATUS_EVENTLOG_FILE_CHANGED = 0xC0000197,
            STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT = 0xC0000198,
            STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT = 0xC0000199,
            STATUS_NOLOGON_SERVER_TRUST_ACCOUNT = 0xC000019A,
            STATUS_DOMAIN_TRUST_INCONSISTENT = 0xC000019B,
            STATUS_FS_DRIVER_REQUIRED = 0xC000019C,
            STATUS_NO_USER_SESSION_KEY = 0xC0000202,
            STATUS_USER_SESSION_DELETED = 0xC0000203,
            STATUS_RESOURCE_LANG_NOT_FOUND = 0xC0000204,
            STATUS_INSUFF_SERVER_RESOURCES = 0xC0000205,
            STATUS_INVALID_BUFFER_SIZE = 0xC0000206,
            STATUS_INVALID_ADDRESS_COMPONENT = 0xC0000207,
            STATUS_INVALID_ADDRESS_WILDCARD = 0xC0000208,
            STATUS_TOO_MANY_ADDRESSES = 0xC0000209,
            STATUS_ADDRESS_ALREADY_EXISTS = 0xC000020A,
            STATUS_ADDRESS_CLOSED = 0xC000020B,
            STATUS_CONNECTION_DISCONNECTED = 0xC000020C,
            STATUS_CONNECTION_RESET = 0xC000020D,
            STATUS_TOO_MANY_NODES = 0xC000020E,
            STATUS_TRANSACTION_ABORTED = 0xC000020F,
            STATUS_TRANSACTION_TIMED_OUT = 0xC0000210,
            STATUS_TRANSACTION_NO_RELEASE = 0xC0000211,
            STATUS_TRANSACTION_NO_MATCH = 0xC0000212,
            STATUS_TRANSACTION_RESPONDED = 0xC0000213,
            STATUS_TRANSACTION_INVALID_ID = 0xC0000214,
            STATUS_TRANSACTION_INVALID_TYPE = 0xC0000215,
            STATUS_NOT_SERVER_SESSION = 0xC0000216,
            STATUS_NOT_CLIENT_SESSION = 0xC0000217,
            STATUS_CANNOT_LOAD_REGISTRY_FILE = 0xC0000218,
            STATUS_DEBUG_ATTACH_FAILED = 0xC0000219,
            STATUS_SYSTEM_PROCESS_TERMINATED = 0xC000021A,
            STATUS_DATA_NOT_ACCEPTED = 0xC000021B,
            STATUS_NO_BROWSER_SERVERS_FOUND = 0xC000021C,
            STATUS_VDM_HARD_ERROR = 0xC000021D,
            STATUS_DRIVER_CANCEL_TIMEOUT = 0xC000021E,
            STATUS_REPLY_MESSAGE_MISMATCH = 0xC000021F,
            STATUS_MAPPED_ALIGNMENT = 0xC0000220,
            STATUS_IMAGE_CHECKSUM_MISMATCH = 0xC0000221,
            STATUS_LOST_WRITEBEHIND_DATA = 0xC0000222,
            STATUS_CLIENT_SERVER_PARAMETERS_INVALID = 0xC0000223,
            STATUS_PASSWORD_MUST_CHANGE = 0xC0000224,
            STATUS_NOT_FOUND = 0xC0000225,
            STATUS_NOT_TINY_STREAM = 0xC0000226,
            STATUS_RECOVERY_FAILURE = 0xC0000227,
            STATUS_STACK_OVERFLOW_READ = 0xC0000228,
            STATUS_FAIL_CHECK = 0xC0000229,
            STATUS_DUPLICATE_OBJECTID = 0xC000022A,
            STATUS_OBJECTID_EXISTS = 0xC000022B,
            STATUS_CONVERT_TO_LARGE = 0xC000022C,
            STATUS_RETRY = 0xC000022D,
            STATUS_FOUND_OUT_OF_SCOPE = 0xC000022E,
            STATUS_ALLOCATE_BUCKET = 0xC000022F,
            STATUS_PROPSET_NOT_FOUND = 0xC0000230,
            STATUS_MARSHALL_OVERFLOW = 0xC0000231,
            STATUS_INVALID_VARIANT = 0xC0000232,
            STATUS_DOMAIN_CONTROLLER_NOT_FOUND = 0xC0000233,
            STATUS_ACCOUNT_LOCKED_OUT = 0xC0000234,
            STATUS_HANDLE_NOT_CLOSABLE = 0xC0000235,
            STATUS_CONNECTION_REFUSED = 0xC0000236,
            STATUS_GRACEFUL_DISCONNECT = 0xC0000237,
            STATUS_ADDRESS_ALREADY_ASSOCIATED = 0xC0000238,
            STATUS_ADDRESS_NOT_ASSOCIATED = 0xC0000239,
            STATUS_CONNECTION_INVALID = 0xC000023A,
            STATUS_CONNECTION_ACTIVE = 0xC000023B,
            STATUS_NETWORK_UNREACHABLE = 0xC000023C,
            STATUS_HOST_UNREACHABLE = 0xC000023D,
            STATUS_PROTOCOL_UNREACHABLE = 0xC000023E,
            STATUS_PORT_UNREACHABLE = 0xC000023F,
            STATUS_REQUEST_ABORTED = 0xC0000240,
            STATUS_CONNECTION_ABORTED = 0xC0000241,
            STATUS_BAD_COMPRESSION_BUFFER = 0xC0000242,
            STATUS_USER_MAPPED_FILE = 0xC0000243,
            STATUS_AUDIT_FAILED = 0xC0000244,
            STATUS_TIMER_RESOLUTION_NOT_SET = 0xC0000245,
            STATUS_CONNECTION_COUNT_LIMIT = 0xC0000246,
            STATUS_LOGIN_TIME_RESTRICTION = 0xC0000247,
            STATUS_LOGIN_WKSTA_RESTRICTION = 0xC0000248,
            STATUS_IMAGE_MP_UP_MISMATCH = 0xC0000249,
            STATUS_INSUFFICIENT_LOGON_INFO = 0xC0000250,
            STATUS_BAD_DLL_ENTRYPOINT = 0xC0000251,
            STATUS_BAD_SERVICE_ENTRYPOINT = 0xC0000252,
            STATUS_LPC_REPLY_LOST = 0xC0000253,
            STATUS_IP_ADDRESS_CONFLICT1 = 0xC0000254,
            STATUS_IP_ADDRESS_CONFLICT2 = 0xC0000255,
            STATUS_REGISTRY_QUOTA_LIMIT = 0xC0000256,
            STATUS_PATH_NOT_COVERED = 0xC0000257,
            STATUS_NO_CALLBACK_ACTIVE = 0xC0000258,
            STATUS_LICENSE_QUOTA_EXCEEDED = 0xC0000259,
            STATUS_PWD_TOO_SHORT = 0xC000025A,
            STATUS_PWD_TOO_RECENT = 0xC000025B,
            STATUS_PWD_HISTORY_CONFLICT = 0xC000025C,
            STATUS_PLUGPLAY_NO_DEVICE = 0xC000025E,
            STATUS_UNSUPPORTED_COMPRESSION = 0xC000025F,
            STATUS_INVALID_HW_PROFILE = 0xC0000260,
            STATUS_INVALID_PLUGPLAY_DEVICE_PATH = 0xC0000261,
            STATUS_DRIVER_ORDINAL_NOT_FOUND = 0xC0000262,
            STATUS_DRIVER_ENTRYPOINT_NOT_FOUND = 0xC0000263,
            STATUS_RESOURCE_NOT_OWNED = 0xC0000264,
            STATUS_TOO_MANY_LINKS = 0xC0000265,
            STATUS_QUOTA_LIST_INCONSISTENT = 0xC0000266,
            STATUS_FILE_IS_OFFLINE = 0xC0000267,
            STATUS_EVALUATION_EXPIRATION = 0xC0000268,
            STATUS_ILLEGAL_DLL_RELOCATION = 0xC0000269,
            STATUS_LICENSE_VIOLATION = 0xC000026A,
            STATUS_DLL_INIT_FAILED_LOGOFF = 0xC000026B,
            STATUS_DRIVER_UNABLE_TO_LOAD = 0xC000026C,
            STATUS_DFS_UNAVAILABLE = 0xC000026D,
            STATUS_VOLUME_DISMOUNTED = 0xC000026E,
            STATUS_WX86_INTERNAL_ERROR = 0xC000026F,
            STATUS_WX86_FLOAT_STACK_CHECK = 0xC0000270,
            STATUS_VALIDATE_CONTINUE = 0xC0000271,
            STATUS_NO_MATCH = 0xC0000272,
            STATUS_NO_MORE_MATCHES = 0xC0000273,
            STATUS_NOT_A_REPARSE_POINT = 0xC0000275,
            STATUS_IO_REPARSE_TAG_INVALID = 0xC0000276,
            STATUS_IO_REPARSE_TAG_MISMATCH = 0xC0000277,
            STATUS_IO_REPARSE_DATA_INVALID = 0xC0000278,
            STATUS_IO_REPARSE_TAG_NOT_HANDLED = 0xC0000279,
            STATUS_REPARSE_POINT_NOT_RESOLVED = 0xC0000280,
            STATUS_DIRECTORY_IS_A_REPARSE_POINT = 0xC0000281,
            STATUS_RANGE_LIST_CONFLICT = 0xC0000282,
            STATUS_SOURCE_ELEMENT_EMPTY = 0xC0000283,
            STATUS_DESTINATION_ELEMENT_FULL = 0xC0000284,
            STATUS_ILLEGAL_ELEMENT_ADDRESS = 0xC0000285,
            STATUS_MAGAZINE_NOT_PRESENT = 0xC0000286,
            STATUS_REINITIALIZATION_NEEDED = 0xC0000287,
            STATUS_ENCRYPTION_FAILED = 0xC000028A,
            STATUS_DECRYPTION_FAILED = 0xC000028B,
            STATUS_RANGE_NOT_FOUND = 0xC000028C,
            STATUS_NO_RECOVERY_POLICY = 0xC000028D,
            STATUS_NO_EFS = 0xC000028E,
            STATUS_WRONG_EFS = 0xC000028F,
            STATUS_NO_USER_KEYS = 0xC0000290,
            STATUS_FILE_NOT_ENCRYPTED = 0xC0000291,
            STATUS_NOT_EXPORT_FORMAT = 0xC0000292,
            STATUS_FILE_ENCRYPTED = 0xC0000293,
            STATUS_WMI_GUID_NOT_FOUND = 0xC0000295,
            STATUS_WMI_INSTANCE_NOT_FOUND = 0xC0000296,
            STATUS_WMI_ITEMID_NOT_FOUND = 0xC0000297,
            STATUS_WMI_TRY_AGAIN = 0xC0000298,
            STATUS_SHARED_POLICY = 0xC0000299,
            STATUS_POLICY_OBJECT_NOT_FOUND = 0xC000029A,
            STATUS_POLICY_ONLY_IN_DS = 0xC000029B,
            STATUS_VOLUME_NOT_UPGRADED = 0xC000029C,
            STATUS_REMOTE_STORAGE_NOT_ACTIVE = 0xC000029D,
            STATUS_REMOTE_STORAGE_MEDIA_ERROR = 0xC000029E,
            STATUS_NO_TRACKING_SERVICE = 0xC000029F,
            STATUS_SERVER_SID_MISMATCH = 0xC00002A0,
            STATUS_DS_NO_ATTRIBUTE_OR_VALUE = 0xC00002A1,
            STATUS_DS_INVALID_ATTRIBUTE_SYNTAX = 0xC00002A2,
            STATUS_DS_ATTRIBUTE_TYPE_UNDEFINED = 0xC00002A3,
            STATUS_DS_ATTRIBUTE_OR_VALUE_EXISTS = 0xC00002A4,
            STATUS_DS_BUSY = 0xC00002A5,
            STATUS_DS_UNAVAILABLE = 0xC00002A6,
            STATUS_DS_NO_RIDS_ALLOCATED = 0xC00002A7,
            STATUS_DS_NO_MORE_RIDS = 0xC00002A8,
            STATUS_DS_INCORRECT_ROLE_OWNER = 0xC00002A9,
            STATUS_DS_RIDMGR_INIT_ERROR = 0xC00002AA,
            STATUS_DS_OBJ_CLASS_VIOLATION = 0xC00002AB,
            STATUS_DS_CANT_ON_NON_LEAF = 0xC00002AC,
            STATUS_DS_CANT_ON_RDN = 0xC00002AD,
            STATUS_DS_CANT_MOD_OBJ_CLASS = 0xC00002AE,
            STATUS_DS_CROSS_DOM_MOVE_FAILED = 0xC00002AF,
            STATUS_DS_GC_NOT_AVAILABLE = 0xC00002B0,
            STATUS_DIRECTORY_SERVICE_REQUIRED = 0xC00002B1,
            STATUS_REPARSE_ATTRIBUTE_CONFLICT = 0xC00002B2,
            STATUS_CANT_ENABLE_DENY_ONLY = 0xC00002B3,
            STATUS_FLOAT_MULTIPLE_FAULTS = 0xC00002B4,
            STATUS_FLOAT_MULTIPLE_TRAPS = 0xC00002B5,
            STATUS_DEVICE_REMOVED = 0xC00002B6,
            STATUS_JOURNAL_DELETE_IN_PROGRESS = 0xC00002B7,
            STATUS_JOURNAL_NOT_ACTIVE = 0xC00002B8,
            STATUS_NOINTERFACE = 0xC00002B9,
            STATUS_DS_ADMIN_LIMIT_EXCEEDED = 0xC00002C1,
            STATUS_DRIVER_FAILED_SLEEP = 0xC00002C2,
            STATUS_MUTUAL_AUTHENTICATION_FAILED = 0xC00002C3,
            STATUS_CORRUPT_SYSTEM_FILE = 0xC00002C4,
            STATUS_DATATYPE_MISALIGNMENT_ERROR = 0xC00002C5,
            STATUS_WMI_READ_ONLY = 0xC00002C6,
            STATUS_WMI_SET_FAILURE = 0xC00002C7,
            STATUS_COMMITMENT_MINIMUM = 0xC00002C8,
            STATUS_REG_NAT_CONSUMPTION = 0xC00002C9,
            STATUS_TRANSPORT_FULL = 0xC00002CA,
            STATUS_DS_SAM_INIT_FAILURE = 0xC00002CB,
            STATUS_ONLY_IF_CONNECTED = 0xC00002CC,
            STATUS_DS_SENSITIVE_GROUP_VIOLATION = 0xC00002CD,
            STATUS_PNP_RESTART_ENUMERATION = 0xC00002CE,
            STATUS_JOURNAL_ENTRY_DELETED = 0xC00002CF,
            STATUS_DS_CANT_MOD_PRIMARYGROUPID = 0xC00002D0,
            STATUS_SYSTEM_IMAGE_BAD_SIGNATURE = 0xC00002D1,
            STATUS_PNP_REBOOT_REQUIRED = 0xC00002D2,
            STATUS_POWER_STATE_INVALID = 0xC00002D3,
            STATUS_DS_INVALID_GROUP_TYPE = 0xC00002D4,
            STATUS_DS_NO_NEST_GLOBALGROUP_IN_MIXEDDOMAIN = 0xC00002D5,
            STATUS_DS_NO_NEST_LOCALGROUP_IN_MIXEDDOMAIN = 0xC00002D6,
            STATUS_DS_GLOBAL_CANT_HAVE_LOCAL_MEMBER = 0xC00002D7,
            STATUS_DS_GLOBAL_CANT_HAVE_UNIVERSAL_MEMBER = 0xC00002D8,
            STATUS_DS_UNIVERSAL_CANT_HAVE_LOCAL_MEMBER = 0xC00002D9,
            STATUS_DS_GLOBAL_CANT_HAVE_CROSSDOMAIN_MEMBER = 0xC00002DA,
            STATUS_DS_LOCAL_CANT_HAVE_CROSSDOMAIN_LOCAL_MEMBER = 0xC00002DB,
            STATUS_DS_HAVE_PRIMARY_MEMBERS = 0xC00002DC,
            STATUS_WMI_NOT_SUPPORTED = 0xC00002DD,
            STATUS_INSUFFICIENT_POWER = 0xC00002DE,
            STATUS_SAM_NEED_BOOTKEY_PASSWORD = 0xC00002DF,
            STATUS_SAM_NEED_BOOTKEY_FLOPPY = 0xC00002E0,
            STATUS_DS_CANT_START = 0xC00002E1,
            STATUS_DS_INIT_FAILURE = 0xC00002E2,
            STATUS_SAM_INIT_FAILURE = 0xC00002E3,
            STATUS_DS_GC_REQUIRED = 0xC00002E4,
            STATUS_DS_LOCAL_MEMBER_OF_LOCAL_ONLY = 0xC00002E5,
            STATUS_DS_NO_FPO_IN_UNIVERSAL_GROUPS = 0xC00002E6,
            STATUS_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED = 0xC00002E7,
            STATUS_MULTIPLE_FAULT_VIOLATION = 0xC00002E8,
            STATUS_CURRENT_DOMAIN_NOT_ALLOWED = 0xC00002E9,
            STATUS_CANNOT_MAKE = 0xC00002EA,
            STATUS_SYSTEM_SHUTDOWN = 0xC00002EB,
            STATUS_DS_INIT_FAILURE_CONSOLE = 0xC00002EC,
            STATUS_DS_SAM_INIT_FAILURE_CONSOLE = 0xC00002ED,
            STATUS_UNFINISHED_CONTEXT_DELETED = 0xC00002EE,
            STATUS_NO_TGT_REPLY = 0xC00002EF,
            STATUS_OBJECTID_NOT_FOUND = 0xC00002F0,
            STATUS_NO_IP_ADDRESSES = 0xC00002F1,
            STATUS_WRONG_CREDENTIAL_HANDLE = 0xC00002F2,
            STATUS_CRYPTO_SYSTEM_INVALID = 0xC00002F3,
            STATUS_MAX_REFERRALS_EXCEEDED = 0xC00002F4,
            STATUS_MUST_BE_KDC = 0xC00002F5,
            STATUS_STRONG_CRYPTO_NOT_SUPPORTED = 0xC00002F6,
            STATUS_TOO_MANY_PRINCIPALS = 0xC00002F7,
            STATUS_NO_PA_DATA = 0xC00002F8,
            STATUS_PKINIT_NAME_MISMATCH = 0xC00002F9,
            STATUS_SMARTCARD_LOGON_REQUIRED = 0xC00002FA,
            STATUS_KDC_INVALID_REQUEST = 0xC00002FB,
            STATUS_KDC_UNABLE_TO_REFER = 0xC00002FC,
            STATUS_KDC_UNKNOWN_ETYPE = 0xC00002FD,
            STATUS_SHUTDOWN_IN_PROGRESS = 0xC00002FE,
            STATUS_SERVER_SHUTDOWN_IN_PROGRESS = 0xC00002FF,
            STATUS_NOT_SUPPORTED_ON_SBS = 0xC0000300,
            STATUS_WMI_GUID_DISCONNECTED = 0xC0000301,
            STATUS_WMI_ALREADY_DISABLED = 0xC0000302,
            STATUS_WMI_ALREADY_ENABLED = 0xC0000303,
            STATUS_MFT_TOO_FRAGMENTED = 0xC0000304,
            STATUS_COPY_PROTECTION_FAILURE = 0xC0000305,
            STATUS_CSS_AUTHENTICATION_FAILURE = 0xC0000306,
            STATUS_CSS_KEY_NOT_PRESENT = 0xC0000307,
            STATUS_CSS_KEY_NOT_ESTABLISHED = 0xC0000308,
            STATUS_CSS_SCRAMBLED_SECTOR = 0xC0000309,
            STATUS_CSS_REGION_MISMATCH = 0xC000030A,
            STATUS_CSS_RESETS_EXHAUSTED = 0xC000030B,
            STATUS_PKINIT_FAILURE = 0xC0000320,
            STATUS_SMARTCARD_SUBSYSTEM_FAILURE = 0xC0000321,
            STATUS_NO_KERB_KEY = 0xC0000322,
            STATUS_HOST_DOWN = 0xC0000350,
            STATUS_UNSUPPORTED_PREAUTH = 0xC0000351,
            STATUS_EFS_ALG_BLOB_TOO_BIG = 0xC0000352,
            STATUS_PORT_NOT_SET = 0xC0000353,
            STATUS_DEBUGGER_INACTIVE = 0xC0000354,
            STATUS_DS_VERSION_CHECK_FAILURE = 0xC0000355,
            STATUS_AUDITING_DISABLED = 0xC0000356,
            STATUS_PRENT4_MACHINE_ACCOUNT = 0xC0000357,
            STATUS_DS_AG_CANT_HAVE_UNIVERSAL_MEMBER = 0xC0000358,
            STATUS_INVALID_IMAGE_WIN_32 = 0xC0000359,
            STATUS_INVALID_IMAGE_WIN_64 = 0xC000035A,
            STATUS_BAD_BINDINGS = 0xC000035B,
            STATUS_NETWORK_SESSION_EXPIRED = 0xC000035C,
            STATUS_APPHELP_BLOCK = 0xC000035D,
            STATUS_ALL_SIDS_FILTERED = 0xC000035E,
            STATUS_NOT_SAFE_MODE_DRIVER = 0xC000035F,
            STATUS_ACCESS_DISABLED_BY_POLICY_DEFAULT = 0xC0000361,
            STATUS_ACCESS_DISABLED_BY_POLICY_PATH = 0xC0000362,
            STATUS_ACCESS_DISABLED_BY_POLICY_PUBLISHER = 0xC0000363,
            STATUS_ACCESS_DISABLED_BY_POLICY_OTHER = 0xC0000364,
            STATUS_FAILED_DRIVER_ENTRY = 0xC0000365,
            STATUS_DEVICE_ENUMERATION_ERROR = 0xC0000366,
            STATUS_WAIT_FOR_OPLOCK = 0x00000367,
            STATUS_MOUNT_POINT_NOT_RESOLVED = 0xC0000368,
            STATUS_INVALID_DEVICE_OBJECT_PARAMETER = 0xC0000369,

            /* STATUS_MCA_OCCURED is not a typo, as per Microsoft's headers */
            STATUS_MCA_OCCURED = 0xC000036A,
            STATUS_DRIVER_BLOCKED_CRITICAL = 0xC000036B,
            STATUS_DRIVER_BLOCKED = 0xC000036C,
            STATUS_DRIVER_DATABASE_ERROR = 0xC000036D,
            STATUS_SYSTEM_HIVE_TOO_LARGE = 0xC000036E,
            STATUS_INVALID_IMPORT_OF_NON_DLL = 0xC000036F,
            STATUS_SMARTCARD_WRONG_PIN = 0xC0000380,
            STATUS_SMARTCARD_CARD_BLOCKED = 0xC0000381,
            STATUS_SMARTCARD_CARD_NOT_AUTHENTICATED = 0xC0000382,
            STATUS_SMARTCARD_NO_CARD = 0xC0000383,
            STATUS_SMARTCARD_NO_KEY_CONTAINER = 0xC0000384,
            STATUS_SMARTCARD_NO_CERTIFICATE = 0xC0000385,
            STATUS_SMARTCARD_NO_KEYSET = 0xC0000386,
            STATUS_SMARTCARD_IO_ERROR = 0xC0000387,
            STATUS_DOWNGRADE_DETECTED = 0xC0000388,
            STATUS_SMARTCARD_CERT_REVOKED = 0xC0000389,
            STATUS_ISSUING_CA_UNTRUSTED = 0xC000038A,
            STATUS_REVOCATION_OFFLINE_C = 0xC000038B,
            STATUS_PKINIT_CLIENT_FAILURE = 0xC000038C,
            STATUS_SMARTCARD_CERT_EXPIRED = 0xC000038D,
            STATUS_DRIVER_FAILED_PRIOR_UNLOAD = 0xC000038E,
            STATUS_SMARTCARD_SILENT_CONTEXT = 0xC000038F,
            STATUS_PER_USER_TRUST_QUOTA_EXCEEDED = 0xC0000401,
            STATUS_ALL_USER_TRUST_QUOTA_EXCEEDED = 0xC0000402,
            STATUS_USER_DELETE_TRUST_QUOTA_EXCEEDED = 0xC0000403,
            STATUS_DS_NAME_NOT_UNIQUE = 0xC0000404,
            STATUS_DS_DUPLICATE_ID_FOUND = 0xC0000405,
            STATUS_DS_GROUP_CONVERSION_ERROR = 0xC0000406,
            STATUS_VOLSNAP_PREPARE_HIBERNATE = 0xC0000407,
            STATUS_USER2USER_REQUIRED = 0xC0000408,
            STATUS_STACK_BUFFER_OVERRUN = 0xC0000409,
            STATUS_NO_S4U_PROT_SUPPORT = 0xC000040A,
            STATUS_CROSSREALM_DELEGATION_FAILURE = 0xC000040B,
            STATUS_REVOCATION_OFFLINE_KDC = 0xC000040C,
            STATUS_ISSUING_CA_UNTRUSTED_KDC = 0xC000040D,
            STATUS_KDC_CERT_EXPIRED = 0xC000040E,
            STATUS_KDC_CERT_REVOKED = 0xC000040F,
            STATUS_PARAMETER_QUOTA_EXCEEDED = 0xC0000410,
            STATUS_HIBERNATION_FAILURE = 0xC0000411,
            STATUS_DELAY_LOAD_FAILED = 0xC0000412,
            STATUS_AUTHENTICATION_FIREWALL_FAILED = 0xC0000413,
            STATUS_VDM_DISALLOWED = 0xC0000414,
            STATUS_HUNG_DISPLAY_DRIVER_THREAD = 0xC0000415,
            STATUS_INSUFFICIENT_RESOURCE_FOR_SPECIFIED_SHARED_SECTION_SIZE = 0xC0000416,
            STATUS_INVALID_CRUNTIME_PARAMETER = 0xC0000417,
            STATUS_NTLM_BLOCKED = 0xC0000418,
            STATUS_ASSERTION_FAILURE = 0xC0000420,
            STATUS_VERIFIER_STOP = 0xC0000421,
            STATUS_CALLBACK_POP_STACK = 0xC0000423,
            STATUS_INCOMPATIBLE_DRIVER_BLOCKED = 0xC0000424,
            STATUS_HIVE_UNLOADED = 0xC0000425,
            STATUS_COMPRESSION_DISABLED = 0xC0000426,
            STATUS_FILE_SYSTEM_LIMITATION = 0xC0000427,
            STATUS_INVALID_IMAGE_HASH = 0xC0000428,
            STATUS_NOT_CAPABLE = 0xC0000429,
            STATUS_REQUEST_OUT_OF_SEQUENCE = 0xC000042A,
            STATUS_IMPLEMENTATION_LIMIT = 0xC000042B,
            STATUS_ELEVATION_REQUIRED = 0xC000042C,
            STATUS_BEYOND_VDL = 0xC0000432,
            STATUS_ENCOUNTERED_WRITE_IN_PROGRESS = 0xC0000433,
            STATUS_PTE_CHANGED = 0xC0000434,
            STATUS_PURGE_FAILED = 0xC0000435,
            STATUS_CRED_REQUIRES_CONFIRMATION = 0xC0000440,
            STATUS_CS_ENCRYPTION_INVALID_SERVER_RESPONSE = 0xC0000441,
            STATUS_CS_ENCRYPTION_UNSUPPORTED_SERVER = 0xC0000442,
            STATUS_CS_ENCRYPTION_EXISTING_ENCRYPTED_FILE = 0xC0000443,
            STATUS_CS_ENCRYPTION_NEW_ENCRYPTED_FILE = 0xC0000444,
            STATUS_CS_ENCRYPTION_FILE_NOT_CSE = 0xC0000445,
            STATUS_INVALID_LABEL = 0xC0000446,
            STATUS_DRIVER_PROCESS_TERMINATED = 0xC0000450,
            STATUS_AMBIGUOUS_SYSTEM_DEVICE = 0xC0000451,
            STATUS_SYSTEM_DEVICE_NOT_FOUND = 0xC0000452,
            STATUS_RESTART_BOOT_APPLICATION = 0xC0000453,
            STATUS_INVALID_TASK_NAME = 0xC0000500,
            STATUS_INVALID_TASK_INDEX = 0xC0000501,
            STATUS_THREAD_ALREADY_IN_TASK = 0xC0000502,
            STATUS_CALLBACK_BYPASS = 0xC0000503,
            STATUS_PORT_CLOSED = 0xC0000700,
            STATUS_MESSAGE_LOST = 0xC0000701,
            STATUS_INVALID_MESSAGE = 0xC0000702,
            STATUS_REQUEST_CANCELED = 0xC0000703,
            STATUS_RECURSIVE_DISPATCH = 0xC0000704,
            STATUS_LPC_RECEIVE_BUFFER_EXPECTED = 0xC0000705,
            STATUS_LPC_INVALID_CONNECTION_USAGE = 0xC0000706,
            STATUS_LPC_REQUESTS_NOT_ALLOWED = 0xC0000707,
            STATUS_RESOURCE_IN_USE = 0xC0000708,
            STATUS_HARDWARE_MEMORY_ERROR = 0xC0000709,
            STATUS_THREADPOOL_HANDLE_EXCEPTION = 0xC000070A,
            STATUS_THREADPOOL_SET_EVENT_ON_COMPLETION_FAILED = 0xC000070B,
            STATUS_THREADPOOL_RELEASE_SEMAPHORE_ON_COMPLETION_FAILED = 0xC000070C,
            STATUS_THREADPOOL_RELEASE_MUTEX_ON_COMPLETION_FAILED = 0xC000070D,
            STATUS_THREADPOOL_FREE_LIBRARY_ON_COMPLETION_FAILED = 0xC000070E,
            STATUS_THREADPOOL_RELEASED_DURING_OPERATION = 0xC000070F,
            STATUS_CALLBACK_RETURNED_WHILE_IMPERSONATING = 0xC0000710,
            STATUS_APC_RETURNED_WHILE_IMPERSONATING = 0xC0000711,
            STATUS_PROCESS_IS_PROTECTED = 0xC0000712,
            STATUS_MCA_EXCEPTION = 0xC0000713,
            STATUS_CERTIFICATE_MAPPING_NOT_UNIQUE = 0xC0000714,
            STATUS_SYMLINK_CLASS_DISABLED = 0xC0000715,
            STATUS_INVALID_IDN_NORMALIZATION = 0xC0000716,
            STATUS_NO_UNICODE_TRANSLATION = 0xC0000717,
            STATUS_ALREADY_REGISTERED = 0xC0000718,
            STATUS_CONTEXT_MISMATCH = 0xC0000719,
            STATUS_PORT_ALREADY_HAS_COMPLETION_LIST = 0xC000071A,
            STATUS_CALLBACK_RETURNED_THREAD_PRIORITY = 0xC000071B,
            STATUS_INVALID_THREAD = 0xC000071C,
            STATUS_CALLBACK_RETURNED_TRANSACTION = 0xC000071D,
            STATUS_CALLBACK_RETURNED_LDR_LOCK = 0xC000071E,
            STATUS_CALLBACK_RETURNED_LANG = 0xC000071F,
            STATUS_CALLBACK_RETURNED_PRI_BACK = 0xC0000720,
            STATUS_CALLBACK_RETURNED_THREAD_AFFINITY = 0xC0000721,
            STATUS_DISK_REPAIR_DISABLED = 0xC0000800,
            STATUS_DS_DOMAIN_RENAME_IN_PROGRESS = 0xC0000801,
            STATUS_DISK_QUOTA_EXCEEDED = 0xC0000802,
            STATUS_CONTENT_BLOCKED = 0xC0000804,
            STATUS_BAD_CLUSTERS = 0xC0000805,
            STATUS_VOLUME_DIRTY = 0xC0000806,
            STATUS_FILE_CHECKED_OUT = 0xC0000901,
            STATUS_CHECKOUT_REQUIRED = 0xC0000902,
            STATUS_BAD_FILE_TYPE = 0xC0000903,
            STATUS_FILE_TOO_LARGE = 0xC0000904,
            STATUS_FORMS_AUTH_REQUIRED = 0xC0000905,
            STATUS_VIRUS_INFECTED = 0xC0000906,
            STATUS_VIRUS_DELETED = 0xC0000907,
            STATUS_BAD_MCFG_TABLE = 0xC0000908,
            STATUS_WOW_ASSERTION = 0xC0009898,
        }
    }
}
