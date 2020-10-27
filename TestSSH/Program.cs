using System;
using System.IO;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using libssh2.core.Interop;

namespace TestSSH
{
    class Program
    {
        public static String SSHUser = "eherzog@post", SSHPwd = "SonzT451F";
        public static IntPtr libSSHSession = IntPtr.Zero, sshChannel = IntPtr.Zero;

        public static void kbd_callback(string name, int name_len,
                         string instruction, int instruction_len,
                         int num_prompts,
                         ref SSH2Library.LIBSSH2_USERAUTH_KBDINT_PROMPT prompts,
                         ref SSH2Library.LIBSSH2_USERAUTH_KBDINT_RESPONSE responses,
                         [Out] out IntPtr @abstract)
        {

            /* (void) name;
                (void) name_len;
                (void) instruction;
                (void) instruction_len; */
            if (num_prompts > 0) {
                responses.text = (IntPtr)Marshal.StringToHGlobalAnsi(SSHPwd); //Copy Managed-String to Unmanaged-char* AND convert Unicode to ASCII
                responses.length = (uint)SSHPwd.Length;
            }
            /* (void) prompts; */
            @abstract = IntPtr.Zero;
        } /* kbd_callback */

        static void Main(string[] args)
        {
            int rc = 0, sshExitCode = -1;
            string cmd = "";
            byte[] readBuffer = new byte[4096], dataBuffer;

            rc = SSH2Library.libssh2_init(0);
            if(rc!= 0)
            {
                Console.WriteLine("ERROR: libssh2 could not be loaded !");
                return;
            }

            IntPtr p_LibSSHVer = SSH2Library.libssh2_version(0);
            //IntPtr ptrCString = (IntPtr)Marshal.StringToHGlobalAnsi(str); //Our actual marshal. This creates a copy of the string in unmanaged memory. This also converts the unicode string used in C# to ascii (char* is ASCII, wchar_t* is Unicode)
            //Marshal.FreeHGlobal(p_LibSSHVer);
            string libSSHVersion = Marshal.PtrToStringAnsi(p_LibSSHVer);  //(IntPtr)(char*)
            
            Console.WriteLine("LibSSH2-Version: " + libSSHVersion);

            //https://www.libssh2.org/examples/ssh2.html
            libSSHSession = SSH2Library.libssh2_session_init();
            //SSH2Library.libssh2_session_init_ex(System.Func<IntPtr, int> Marshal.AllocHGlobal, System.Func < IntPtr, IntPtr > Marshal.FreeHGlobal, System.Func < IntPtr, IntPtr, IntPtr > Marshal.ReAllocHGlobal, ...);
            Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                s.Connect("10.0.21.254", 22);
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    rc = SSH2Library.libssh2_session_handshake_all(libSSHSession, (IntPtr)s.Handle, 0);
                else
                    rc = SSH2Library.libssh2_session_handshake_all(libSSHSession, IntPtr.Zero, (int)s.Handle);
                if (rc != 0)
                {
                    throw new Exception("SSH-Handshake failed.");
                }

                /* check what authentication methods are available */
                IntPtr p_userauthlist = SSH2Library.libssh2_userauth_list(libSSHSession, SSHUser, (uint)SSHUser.Length);
                String userauthlist = Marshal.PtrToStringAnsi(p_userauthlist);
                Marshal.FreeHGlobal(p_userauthlist);

                int auth_pw = 0;
                if ((userauthlist != null) && (userauthlist.Length > 0))
                {
                    if (userauthlist.Contains("keyboard-interactive"))
                        auth_pw |= (int)1; // AuthenticationType.KeyboardInteractive;
                    if (userauthlist.Contains("password"))
                        auth_pw |= (int)2; // AuthenticationType.Password;
                    if (userauthlist.Contains("publickey"))
                        auth_pw |= (int)4;  // AuthenticationType.PublicKey;
                }
                else
                {
                    auth_pw = 255;
                }

                if ((auth_pw & (int)1) == (int)1)
                {
                    SSH2Library.LIBSSH2_USERAUTH_KBDINT_RESPONSE_FUNC @cbKbInteractive = new SSH2Library.LIBSSH2_USERAUTH_KBDINT_RESPONSE_FUNC(kbd_callback);
                    rc = SSH2Library.libssh2_userauth_keyboard_interactive(libSSHSession, SSHUser, @cbKbInteractive);
                }
                else if ((auth_pw & (int)2) == (int)2)
                {
                    rc = SSH2Library.libssh2_userauth_password(libSSHSession, SSHUser, SSHPwd);
                } else
                {
                    //Public-Key-Auth...
                }
                if (rc != 0)
                {
                    throw new Exception("SSH-Login failed.");
                }

                /* Request a shell */
                sshChannel = SSH2Library.libssh2_channel_open_session(libSSHSession);
                if(sshChannel == IntPtr.Zero)
                {
                    throw new Exception("SSH-Channel open failed.");
                }
                rc = SSH2Library.libssh2_channel_request_pty(sshChannel, "xterm");  //vt100, kterm, xterm
                if (rc != 0)
                {
                    throw new Exception("SSH-Request PTY failed.");
                }
                /* Open a SHELL on that pty */
                rc = SSH2Library.libssh2_channel_shell(sshChannel);
                if (rc != 0)
                {
                    throw new Exception("SSH-Shell failed.");
                }

                //Start Receive-Thread:
                //Set SSH-Connection to Blocking- or	1
                //		NON-Blocking- Mode:             0
                SSH2Library.libssh2_session_set_blocking(libSSHSession, 0);
                Thread th = new Thread(new ThreadStart(AsyncReceive));
                th.Start();


                //rc = SSH2Library.libssh2_channel_read(sshChannel, readBuffer);
                //if (rc > 0)
                //    Console.WriteLine("Prompt: " + System.Text.Encoding.ASCII.GetString(readBuffer));

                cmd = "show version\n";
                dataBuffer = System.Text.Encoding.ASCII.GetBytes(cmd);
                rc = SSH2Library.libssh2_channel_write(sshChannel, dataBuffer);

                System.Threading.Thread.Sleep(2000);

                cmd = "show running-config\n";
                dataBuffer = System.Text.Encoding.ASCII.GetBytes(cmd);
                rc = SSH2Library.libssh2_channel_write(sshChannel, dataBuffer);

                //System.Threading.Thread.Sleep(500);
                /*while ((sshChannel != IntPtr.Zero) && (SSH2Library.libssh2_channel_eof(sshChannel) == 0))
                {
                    rc = SSH2Library.libssh2_channel_read(sshChannel, readBuffer);
                    Console.WriteLine(System.Text.Encoding.ASCII.GetString(readBuffer));
                } */

                Console.WriteLine("Press any Key to stop reading from SSH-Channel...");
                Console.ReadKey();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }

            if (sshChannel != IntPtr.Zero)
            {
                sshExitCode = SSH2Library.libssh2_channel_get_exit_status(sshChannel);
                rc = SSH2Library.libssh2_channel_close(sshChannel);
                rc = SSH2Library.libssh2_channel_free(sshChannel);
                sshChannel = IntPtr.Zero;
            }
            if(libSSHSession != IntPtr.Zero)
            {
                rc = SSH2Library.libssh2_session_disconnect(libSSHSession, "Normal Shutdown");
                rc = SSH2Library.libssh2_session_free(libSSHSession);
                libSSHSession = IntPtr.Zero;
            }
            if ((s != null) && (s.Connected))
            {
                s.Close();
            }
            if(s!=null)
            {
                s.Dispose();
                s = null;
            }
            SSH2Library.libssh2_exit();

            Console.WriteLine("Press any Key to exit...");
            Console.ReadKey();
        }
        
        public static void AsyncReceive()
        {
            int recvBytes = 0, rc = 0, recvCounter = 0;
            byte[] reBuf = new byte[0x1000], dataBuffer;
            string strRecvData = "", strCmd = "";
            System.Text.RegularExpressions.Regex re = new System.Text.RegularExpressions.Regex(".*-+[ ]?more[ ]?-+", System.Text.RegularExpressions.RegexOptions.IgnoreCase);

            while (sshChannel != IntPtr.Zero)
            {
                try
                {
                    recvBytes = SSH2Library.libssh2_channel_read(sshChannel, reBuf);
                    if (recvBytes > 0)
                    {
                        recvCounter++;
                        Console.WriteLine("Recv-" + recvCounter.ToString() + ":\n=================================");
                        strRecvData = System.Text.Encoding.ASCII.GetString(reBuf, 0, recvBytes);
                        Console.WriteLine(strRecvData + "\n===*******************************************====");

                        if (re.IsMatch(strRecvData))
                        {
                            strCmd = " ";
                            dataBuffer = System.Text.Encoding.ASCII.GetBytes(strCmd);
                            rc = SSH2Library.libssh2_channel_write(sshChannel, dataBuffer);
                        }
                    } else
                        Thread.Sleep(100);
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                }
            }
        }
    }
}
