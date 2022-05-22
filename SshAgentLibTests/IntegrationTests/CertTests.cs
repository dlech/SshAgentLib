// SPDX-License-Identifier: MIT
// Copyright (c) 2022 David Lechner <david@lechnology.com>

using System.Diagnostics;
using System.IO;
using System.Text;
using dlech.SshAgentLib;
using NUnit.Framework;

using static SshAgentLibTests.Helpers;

namespace SshAgentLibTests.IntegrationTests
{
    // This test fixture requires that the `docker` and `ssh` command line
    // utilities are installed an are in the PATH. It also requires that a
    // Docker imaged named `openssh-cert-test` has been created using the
    // Dockerfile in `docker/cert_test`. Also, file permissions of the private
    // key file must be fixed so that the `ssh` command doesn't complain.
    [TestFixture, Ignore("requires manual configuration before running")]
    public class CertTests
    {
        [Test]
        public void TestUnixAgent()
        {
            const string socketFileName = "cert.test.socket";

            if (File.Exists(socketFileName))
            {
                File.Delete(socketFileName);
            }

            using (var agent = new UnixAgent())
            {
                agent.StartUnixSocket(socketFileName);
                agent.AddKeyFromFile(
                    GetResourceFilePath("CertData", "test_key"),
                    () => Encoding.UTF8.GetBytes(ReadStringResourceFile("CertData", "pw"))
                );

                using (var server = new Process())
                {
                    server.StartInfo.FileName = "docker";
                    server.StartInfo.Arguments = "run --rm -p 22222:22 openssh-cert-test";
                    // This suppresses the debug output. Can be temporarily set to true false if needed.
                    server.StartInfo.RedirectStandardError = true;
                    server.StartInfo.UseShellExecute = false;
                    server.StartInfo.CreateNoWindow = true;
                    server.Start();

                    try
                    {
                        // The server should not have exited at this point.
                        // We also need some delay before the port 22222 can be used.
                        Assume.That(server.WaitForExit(1000), Is.False);

                        var knownHostsFile = GetResourceFilePath("CertData", "known_hosts");

                        using (var ssh = new Process())
                        {
                            ssh.StartInfo.FileName = "ssh";
                            ssh.StartInfo.Arguments =
                                $"test@localhost -p 22222 -o UserKnownHostsFile={knownHostsFile} true";
                            ssh.StartInfo.Environment["SSH_AUTH_SOCK"] = Path.GetFullPath(
                                socketFileName
                            );
                            ssh.StartInfo.UseShellExecute = false;
                            ssh.StartInfo.CreateNoWindow = true;
                            // disable the two lines below for debugging
                            ssh.StartInfo.RedirectStandardInput = true;
                            ssh.StartInfo.RedirectStandardError = true;

                            ssh.Start();
                            ssh.WaitForExit();
                            Assert.That(ssh.ExitCode, Is.Zero);
                        }

                        server.WaitForExit(1000);
                    }
                    finally
                    {
                        // the docker container does not stop automatically
                        // unless the SSH login was successfull, so we need
                        // to be sure that it gets stopped even on failure.
                        if (!server.HasExited)
                        {
                            server.Kill();
                            server.WaitForExit();
                        }
                    }
                }
            }
        }
    }
}
