using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using libssh2.core.Interop;

namespace TestSSH
{
    class Program
    {
        public static String SSHUser = "cisco", SSHPwd = "cisco";
        private static object libSSH2Lock;
        private static bool RecvErr = false;
        public static IntPtr libSSHSession = IntPtr.Zero, sshChannel = IntPtr.Zero;
        private static int dstPort = 22;
        private static bool DebugFlag = false;
        private static bool DataRecvied = false;
        private static string recvData = "", strPrompt = "";
        private static bool Wait4Input = false;

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

        static int Main(string[] args)
        {
            int rc = 0, sshExitCode = -1;
            string cmd = "";
            byte[] readBuffer = new byte[4096], dataBuffer;
            string DeviceIP = "";
            bool bCmdReady = false;
            System.Text.RegularExpressions.Regex rePrompt = new System.Text.RegularExpressions.Regex(@".*[#>][ \n\r]*$", System.Text.RegularExpressions.RegexOptions.IgnoreCase);

            foreach (string param in args)
            {
                if (param.ToLower().StartsWith("/d:"))
                {
                    DeviceIP = param.Substring(3);
                }else if (param.ToLower().StartsWith("/port:"))
                {
                    string strPort = param.Substring(6);
                    if(int.TryParse(strPort, out dstPort))
                    {
                    }
                    else
                    {
                        Console.WriteLine("Parameter port  was in wrong format !\n   Valied values are 1-65535.\n   Now we use port: 22.");
                    }
                } else if (param.ToLower().StartsWith("/u:"))
                {
                    SSHUser = param.Substring(3);
                }
                else if (param.ToLower().StartsWith("/p:"))
                {
                    SSHPwd = param.Substring(3);
                }
                else if (param.ToLower().StartsWith("/debug"))
                {
                    DebugFlag = true;
                }
                else if (param.ToLower().StartsWith("/wait"))
                {
                    Wait4Input = true;
                }
                else
                {
                    Console.WriteLine("Usage:");
                    Console.WriteLine("\t/d:10.1.2.3               IP or Hostname of target Device.");
                    Console.WriteLine("\t/u:Username               Username.");
                    Console.WriteLine("\t/p:Pwd                    Password.");
                    Console.WriteLine("\t/port:22                  TCP-Port.");
                    Console.WriteLine("\t/Wait                     optional: Wait for your commands entered by Keyboard.");
                    Console.WriteLine("\t/Debug                    optional: Enable Debug-Mode.");

                    return(255);
                }
            }

            libSSH2Lock = new object();

            SSH2Library.Open(DebugFlag);
            rc = SSH2Library.libssh2_init(0);
            if(rc!= 0)
            {
                Console.WriteLine("ERROR: libssh2 could not be loaded !");
                return(2);
            }

            IntPtr p_LibSSHVer = SSH2Library.libssh2_version(0);
            string libSSHVersion = Marshal.PtrToStringAnsi(p_LibSSHVer);  //(IntPtr)(char*)            
            Console.WriteLine("LibSSH2-Version: " + libSSHVersion);


            Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                IPAddressList destIPs = ResolveHost(DeviceIP);

                foreach (IPAddress addr in destIPs.AvailableAddresses)
                {
                    try
                    {
                        s.Connect(addr, dstPort);
                        break;
                    }catch(Exception ex)
                    {
                        //If we got more IP´s for the host from DNS,
                        //try to connect to next IP...
                        Console.WriteLine("Error: Connection to IP {0} failed.\n{1}", addr.ToString(), ex.Message);
                    }
                }
                if (!s.Connected)
                {
                    s.Dispose();
                    s = null;

                    SSH2Library.libssh2_exit();
                    SSH2Library.Close();
                    return (1);
                }


                //https://www.libssh2.org/examples/ssh2.html
                libSSHSession = SSH2Library.libssh2_session_init();
                //libSSHSession = SSH2Library.libssh2_session_init(true);

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

                if (Wait4Input)
                {
                    cmd = "";
                    Console.WriteLine("Press q  to exit.");
                    while (!cmd.Equals("q") && !RecvErr)
                    {
                        Console.Write("type cmd> ");
                        cmd = Console.ReadLine();
                        if (cmd.Equals("q"))
                        {

                        } else
                        {
                            cmd += "\n";
                            dataBuffer = System.Text.Encoding.ASCII.GetBytes(cmd);
                            Monitor.Enter(libSSH2Lock);
                            DataRecvied = false;
                            rc = SSH2Library.libssh2_channel_write(sshChannel, dataBuffer);
                            Monitor.Exit(libSSH2Lock);
                        }
                    }
                }
                else
                {
                    //Detect prompt:
                    cmd = "\n";
                    dataBuffer = System.Text.Encoding.ASCII.GetBytes(cmd);
                    Monitor.Enter(libSSH2Lock);
                    DataRecvied = false;
                    recvData = "";
                    rc = SSH2Library.libssh2_channel_write(sshChannel, dataBuffer);
                    Monitor.Exit(libSSH2Lock);

                    System.Threading.Thread.Sleep(200);
                    while (strPrompt.Length == 0)
                    {
                        while ((!DataRecvied) && !RecvErr)
                        {
                            if (!DataRecvied && !RecvErr)
                                System.Threading.Thread.Sleep(100);
                        }
                        if (DataRecvied)
                        {
                            Monitor.Enter(libSSH2Lock);
                            if (rePrompt.IsMatch(recvData))
                            {
                                //Check for "local Echo"-Data
                                strPrompt = recvData.Substring(recvData.Length / 2);
                                if (recvData.StartsWith(strPrompt))
                                {

                                } else
                                    strPrompt = recvData;
                                if (DebugFlag)
                                    Console.WriteLine("Found prompt: " + strPrompt);
                            }
                            else
                            {
                                DataRecvied = false;
                            }
                            Monitor.Exit(libSSH2Lock);
                        }
                    }

                    //Execute Commands:
                    string[] CMDs = { "show version\n", "show running-config\n" };
                    for (int i = 0; i < CMDs.Length; i++)
                    {
                        cmd = CMDs[i];
                        dataBuffer = System.Text.Encoding.ASCII.GetBytes(cmd);
                        Monitor.Enter(libSSH2Lock);
                        DataRecvied = false;
                        recvData = "";
                        rc = SSH2Library.libssh2_channel_write(sshChannel, dataBuffer);
                        Monitor.Exit(libSSH2Lock);

                        //In syncron-Mode you will wait now for the response:
                        /*while ((sshChannel != IntPtr.Zero) && (SSH2Library.libssh2_channel_eof(sshChannel) == 0))
                        {
                            rc = SSH2Library.libssh2_channel_read(sshChannel, readBuffer);
                            Console.WriteLine(System.Text.Encoding.ASCII.GetString(readBuffer));
                        } */

                        bCmdReady = false;
                        while ((!bCmdReady) && !RecvErr)
                        {
                            if (!DataRecvied && !RecvErr)
                                System.Threading.Thread.Sleep(100);
                            else if(DataRecvied)
                            {
                                Monitor.Enter(libSSH2Lock);
                                if(recvData.EndsWith(strPrompt))
                                {
                                    bCmdReady = true;
                                    Console.WriteLine(recvData);
                                } else
                                {
                                    DataRecvied = false;
                                }
                                Monitor.Exit(libSSH2Lock);
                            }
                        }
                        if (RecvErr)
                            break;
                    }
                }
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
            SSH2Library.Close();
            libSSH2Lock = null;

            Console.WriteLine("Press any Key to exit...");
            Console.ReadKey();
            return (0);
        }
        
        public static void AsyncReceive()
        {
            int ErrCode = 0, l = 0;
            string ErrorMsg = "", strRecvData = "";
            int recvBytes = 0, rc1 = 0, recvCounter = 0;
            byte[] reBuf = new byte[0x1000], dataBuffer;
            string strCmd = "";
            string[] recvLines = null;
            System.Text.RegularExpressions.Regex reMore = new System.Text.RegularExpressions.Regex(".*-+[ ]?more[ ]?-+", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            System.Text.RegularExpressions.Regex reEnter = new System.Text.RegularExpressions.Regex(".*press.*enter.*", System.Text.RegularExpressions.RegexOptions.IgnoreCase);

            while ((sshChannel != IntPtr.Zero) && !RecvErr)
            {
                try
                {
                    Monitor.Enter(libSSH2Lock);
                    recvBytes = SSH2Library.libssh2_channel_read(sshChannel, ref reBuf);
                    Monitor.Exit(libSSH2Lock);
                    if (recvBytes > 0)
                    {
                        recvCounter++;
                        if (DebugFlag)
                            Console.WriteLine("Recv-" + recvCounter.ToString() + ":\n=================================");
                        strRecvData = System.Text.Encoding.ASCII.GetString(reBuf, 0, recvBytes);
                        if (DebugFlag)
                            Console.WriteLine(strRecvData + "\n===*******************************************====");
                        else if(Wait4Input)
                            Console.WriteLine(strRecvData);

                        if (reMore.IsMatch(strRecvData))
                        {
                            Monitor.Enter(libSSH2Lock);
                            strCmd = " ";
                            dataBuffer = System.Text.Encoding.ASCII.GetBytes(strCmd);
                            recvLines = strRecvData.Split("\n");
                            for(l=0; l < (recvLines.Length-1); l++)
                                recvData += recvLines[l] + "\n";

                            rc1 = SSH2Library.libssh2_channel_write(sshChannel, dataBuffer);
                            Monitor.Exit(libSSH2Lock);
                        } else if (reEnter.IsMatch(strRecvData))
                        {
                            Monitor.Enter(libSSH2Lock);
                            strCmd = "\n";
                            dataBuffer = System.Text.Encoding.ASCII.GetBytes(strCmd);
                            recvLines = strRecvData.Split("\n");
                            for (l = 0; l < (recvLines.Length - 1); l++)
                                recvData += recvLines[l] + "\n";

                            rc1 = SSH2Library.libssh2_channel_write(sshChannel, dataBuffer);
                            Monitor.Exit(libSSH2Lock);
                        }
                        else
                        {
                            Monitor.Enter(libSSH2Lock);
                            recvData += strRecvData;
                            DataRecvied = true;
                            Monitor.Exit(libSSH2Lock);
                        }
                    } else if ((recvBytes < 0) && (recvBytes != SSH2Library.LIBSSH2_ERROR_EAGAIN)) {
                        ErrCode = recvBytes;

                        IntPtr pErrMsg = IntPtr.Zero;
                        int ErrMsgLen = 0;
                        Monitor.Enter(libSSH2Lock);
                        try
                        {
                            if (libSSHSession != IntPtr.Zero)
                            {
                                ErrCode = SSH2Library.libssh2_session_last_error(libSSHSession, ref pErrMsg, out ErrMsgLen, 0);

                                if (ErrCode != 0)
                                {
                                    if (ErrMsgLen > 0)
                                    {
                                        ErrorMsg = Marshal.PtrToStringAnsi(pErrMsg, ErrMsgLen);
                                        Console.WriteLine("Error: " + ErrCode.ToString() + " / " + ErrorMsg);
                                    }
                                    else
                                    {
                                        Console.WriteLine("Error: Receive-Error " + ErrCode.ToString());
                                    }
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                        }
                        RecvErr = true;
                        Monitor.Exit(libSSH2Lock);
                    } else
                        Thread.Sleep(100);
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                }
            }
        }

        private static IPAddressList ResolveHost(string IPorHost)
        {
            IPAddressList _addressSet;
            IPAddress address = null;

            if (IPAddress.TryParse(IPorHost, out address))
            {
                _addressSet = new IPAddressList(address);
            }
            else
            {
                //Try to resolve Destination via DNS:
                _addressSet = new IPAddressList(IPorHost);
            }

            return (_addressSet);
        }
    }
}
