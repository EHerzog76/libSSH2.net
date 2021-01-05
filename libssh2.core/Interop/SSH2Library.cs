using System;
using System.IO;
using System.Text;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.ExceptionServices;
using System.Collections;
using System.Collections.Generic;

namespace libssh2.core.Interop
{
    public static class SSH2Library
    {
        private static volatile object SSH2Lock;
        private const string libSSH2Name = InteropRuntimeConfig.LibraryName + ".dll";
        public static UnmanagedLibrary libVCRun = null;
        public static UnmanagedLibrary libSSH2 = null;
        public static UnmanagedLibrary libZLib1 = null;
#if WithLibTest
        public static UnmanagedLibrary libTest = null;
#endif
        private static volatile bool libSSH2Init;

        static SSH2Library()
        {
            libSSH2Init = false;
            SSH2Lock = new object();
        }

        public static void Open(bool DebugFlag) {
            string thisAssemblyPath = new Uri(typeof(SSH2Library).Assembly.CodeBase).LocalPath;
            string thisAssemblyFolder = Path.GetDirectoryName(thisAssemblyPath);
            List<string> libPaths = new List<string>();
            ArrayList libArray = new ArrayList();

            string dllDirectoryPath = Path.Combine(thisAssemblyFolder, "libssh2");
            string vcruntimePath = Path.Combine(dllDirectoryPath, "vcruntime140");
            string libssh2Path = Path.Combine(dllDirectoryPath, "libssh2");
            string zlib1Path = Path.Combine(dllDirectoryPath, "zlib1");
            /*
            try
            {
                if (libVCRun == null)
                    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    {
                        libPaths.Add(vcruntimePath);
                        //libPaths.Add("C:\\Windows\\System32\\vcruntime140");
                        libPaths.Add("vcruntime140");
                        libVCRun = new UnmanagedLibrary(libPaths.ToArray(), DebugFlag);
                        libPaths.Clear();
                    }
            } catch(Exception ex)
            {
                Console.WriteLine("Error: Loading vcruntime140.dll !\n" + ex.Message);
                libPaths.Clear();
            }
            */
            /*
            try {
                if (libZLib1 == null)
                {
                    libPaths.Add(Path.Combine(thisAssemblyFolder, "zlib1"));
                    libPaths.Add(Path.Combine(thisAssemblyFolder, "zlib"));
                    libPaths.Add(zlib1Path);
                    libPaths.Add("zlib1");
                    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    {
                        libPaths.Add(zlib1Path);
                    }
                    else
                    {
                        libPaths.Add(zlib1Path);
                    }
                    libZLib1 = new UnmanagedLibrary(libPaths.ToArray(), DebugFlag);
                    libPaths.Clear();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: Loading library zlib1 !\n" + ex.Message);
                libPaths.Clear();
            }
            */
#if WithLibTest
            if (libTest == null)
            {
                try
                {
                    libPaths.Add(Path.Combine(thisAssemblyFolder, "TestDll"));
                    libTest = new UnmanagedLibrary(libPaths.ToArray(), DebugFlag);
                    libPaths.Clear();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error: Loading library TestDll !\n" + ex.Message);
                    libPaths.Clear();
                }
            }
#endif

            if (libSSH2 != null)
                return;

            try {
                //Work-a-Round...
                //if (pre_libssh2_init(0) == 0)
                //    pre_libssh2_exit();

                libPaths.Add(Path.Combine(thisAssemblyFolder, "libssh2"));
                libPaths.Add(libssh2Path);
                libPaths.Add("libssh2");
                libSSH2 = new UnmanagedLibrary(libPaths.ToArray(), DebugFlag);
                libPaths.Clear();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: Loading library libssh2 !\n" + ex.Message);
                libPaths.Clear();
            }

#if WithLibTest
            try
            {
                testdll_write2console = libTest.GetNativeMethodDelegate<del_testdll_write2console>("write2console");
            }
            catch(Exception ex)
            {
                Console.WriteLine("Error: Loading functions from  TestDll !\n" + ex.Message);
            }
#endif

            try {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    libssh2_session_handshake_w = libSSH2.GetNativeMethodDelegate<libssh2_session_handshake_win>("libssh2_session_handshake");
                } else
                {
                    libssh2_session_handshake_l = libSSH2.GetNativeMethodDelegate<libssh2_session_handshake_linux>("libssh2_session_handshake");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: Loading function  libssh2_session_handshake !\n" + ex.Message);
            }

            try
            {
                libssh2_init = libSSH2.GetNativeMethodDelegate<del_libssh2_init>("libssh2_init");        
                libssh2_exit = libSSH2.GetNativeMethodDelegate<del_libssh2_exit>("libssh2_exit");
                libssh2_free = libSSH2.GetNativeMethodDelegate<del_libssh2_free>("libssh2_free");
                libssh2_version = libSSH2.GetNativeMethodDelegate<del_libssh2_version>("libssh2_version");
                libssh2_session_init_ex = libSSH2.GetNativeMethodDelegate<del_libssh2_session_init_ex>("libssh2_session_init_ex");
                libssh2_session_set_blocking = libSSH2.GetNativeMethodDelegate<del_libssh2_session_set_blocking>("libssh2_session_set_blocking");
                libssh2_session_get_blocking = libSSH2.GetNativeMethodDelegate<del_libssh2_session_get_blocking>("libssh2_session_get_blocking");
                libssh2_session_block_directions = libSSH2.GetNativeMethodDelegate<del_libssh2_session_block_directions>("libssh2_session_block_directions");
                libssh2_session_flag = libSSH2.GetNativeMethodDelegate<del_libssh2_session_flag>("libssh2_session_flag");
                libssh2_keepalive_config = libSSH2.GetNativeMethodDelegate<del_libssh2_keepalive_config>("libssh2_keepalive_config");
                libssh2_keepalive_send = libSSH2.GetNativeMethodDelegate<del_libssh2_keepalive_send>("libssh2_keepalive_send");
                libssh2_session_banner_set = libSSH2.GetNativeMethodDelegate<del_libssh2_session_banner_set>("libssh2_session_banner_set");
                libssh2_banner_set = libSSH2.GetNativeMethodDelegate<del_libssh2_banner_set>("libssh2_banner_set");
                libssh2_session_banner_get = libSSH2.GetNativeMethodDelegate<del_libssh2_session_banner_get>("libssh2_session_banner_get");
                libssh2_trace = libSSH2.GetNativeMethodDelegate<del_libssh2_trace>("libssh2_trace");
                libssh2_channel_open_ex = libSSH2.GetNativeMethodDelegate<del_libssh2_channel_open_ex>("libssh2_channel_open_ex");
                libssh2_session_last_error = libSSH2.GetNativeMethodDelegate<del_libssh2_session_last_error>("libssh2_session_last_error");
                libssh2_session_last_errno = libSSH2.GetNativeMethodDelegate<del_libssh2_session_last_errno>("libssh2_session_last_errno");
                libssh2_session_set_last_error = libSSH2.GetNativeMethodDelegate<del_libssh2_session_set_last_error>("libssh2_session_set_last_error");
                libssh2_channel_setenv_ex = libSSH2.GetNativeMethodDelegate<del_libssh2_channel_setenv_ex>("libssh2_channel_setenv_ex");
                libssh2_channel_process_startup = libSSH2.GetNativeMethodDelegate<del_libssh2_channel_process_startup>("libssh2_channel_process_startup");
                libssh2_channel_read_ex = libSSH2.GetNativeMethodDelegate<del_libssh2_channel_read_ex>("libssh2_channel_read_ex");
                libssh2_channel_get_exit_status = libSSH2.GetNativeMethodDelegate<del_libssh2_channel_get_exit_status>("libssh2_channel_get_exit_status");
                libssh2_channel_request_pty_ex = libSSH2.GetNativeMethodDelegate<del_libssh2_channel_request_pty_ex>("libssh2_channel_request_pty_ex");
                libssh2_channel_send_eof = libSSH2.GetNativeMethodDelegate<del_libssh2_channel_send_eof>("libssh2_channel_send_eof");
                libssh2_channel_eof = libSSH2.GetNativeMethodDelegate<del_libssh2_channel_eof>("libssh2_channel_eof");
                libssh2_channel_wait_eof = libSSH2.GetNativeMethodDelegate<del_libssh2_channel_wait_eof>("libssh2_channel_wait_eof");
                libssh2_channel_close = libSSH2.GetNativeMethodDelegate<del_libssh2_channel_close>("libssh2_channel_close");
                libssh2_channel_wait_closed = libSSH2.GetNativeMethodDelegate<del_libssh2_channel_wait_closed>("libssh2_channel_wait_closed");
                libssh2_channel_free = libSSH2.GetNativeMethodDelegate<del_libssh2_channel_free>("libssh2_channel_free");
                libssh2_session_disconnect_ex = libSSH2.GetNativeMethodDelegate<del_libssh2_session_disconnect_ex>("libssh2_session_disconnect_ex");
                libssh2_session_free = libSSH2.GetNativeMethodDelegate<del_libssh2_session_free>("libssh2_session_free");
                libssh2_hostkey_hash = libSSH2.GetNativeMethodDelegate<del_libssh2_hostkey_hash>("libssh2_hostkey_hash");
                libssh2_session_hostkey = libSSH2.GetNativeMethodDelegate<del_libssh2_session_hostkey>("libssh2_session_hostkey");
                libssh2_session_supported_algs = libSSH2.GetNativeMethodDelegate<del_libssh2_session_supported_algs>("libssh2_session_supported_algs");
                libssh2_session_method_pref = libSSH2.GetNativeMethodDelegate<del_libssh2_session_method_pref>("libssh2_session_method_pref");
                libssh2_session_methods = libSSH2.GetNativeMethodDelegate<del_libssh2_session_methods>("libssh2_session_methods");
                libssh2_channel_flush_ex = libSSH2.GetNativeMethodDelegate<del_libssh2_channel_flush_ex>("libssh2_channel_flush_ex");
                libssh2_channel_write_ex = libSSH2.GetNativeMethodDelegate<del_libssh2_channel_write_ex>("libssh2_channel_write_ex");
                libssh2_userauth_password_ex = libSSH2.GetNativeMethodDelegate<del_libssh2_userauth_password_ex>("libssh2_userauth_password_ex");
                libssh2_userauth_list = libSSH2.GetNativeMethodDelegate<del_libssh2_userauth_list>("libssh2_userauth_list");        
                libssh2_userauth_authenticated = libSSH2.GetNativeMethodDelegate<del_libssh2_userauth_authenticated>("libssh2_userauth_authenticated");
                libssh2_userauth_keyboard_interactive_ex = libSSH2.GetNativeMethodDelegate<del_libssh2_userauth_keyboard_interactive_ex>("libssh2_userauth_keyboard_interactive_ex");
                libssh2_userauth_publickey_fromfile_ex = libSSH2.GetNativeMethodDelegate<del_libssh2_userauth_publickey_fromfile_ex>("libssh2_userauth_publickey_fromfile_ex");
                libssh2_userauth_publickey = libSSH2.GetNativeMethodDelegate<del_libssh2_userauth_publickey>("libssh2_userauth_publickey");
                libssh2_userauth_hostbased_fromfile_ex = libSSH2.GetNativeMethodDelegate<del_libssh2_userauth_hostbased_fromfile_ex>("libssh2_userauth_hostbased_fromfile_ex");
                libssh2_userauth_publickey_frommemory = libSSH2.GetNativeMethodDelegate<del_libssh2_userauth_publickey_frommemory>("libssh2_userauth_publickey_frommemory");
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: Loading functions from libssh2 failed !\n" + ex.Message);
            }
        }

        public static void Close()
        {
            lock (SSH2Lock)
            {
                if (libSSH2 != null)
                {
                    libSSH2.Close();
                    libSSH2 = null;
                }
                if (libZLib1 != null)
                {
                    libZLib1.Close();
                    libZLib1 = null;
                }
#if WithLibTest
            if(libTest != null)
            {
                libTest.Close();
                libTest = null;
            }
#endif
                if (libVCRun != null)
                {
                    libVCRun.Close();
                    libVCRun = null;
                }
            }
        }

        public static byte[] UTF16toUTF8(string srcString)
        {
            byte[] utf8String = new byte[srcString.Length + 2];
            Encoding.UTF8.GetBytes(srcString, 0, srcString.Length, utf8String, 0);
            return (utf8String);
        }
        public static byte[] UTF16toASCII(string srcString)
        {
            byte[] asciiString = new byte[srcString.Length + 2]; 
            Encoding.ASCII.GetBytes(srcString, 0, srcString.Length, asciiString, 0);
            return (asciiString);

            // Write the UTF-8 and ASCII encoded byte arrays. 
            //output.WriteLine("UTF-8  Bytes: {0}", BitConverter.ToString(utf8String));
            //output.WriteLine("ASCII  Bytes: {0}", BitConverter.ToString(asciiString));
        }
        public static string PtrToStringUtf8(IntPtr ptr) // aPtr is nul-terminated
        {
            if (ptr == IntPtr.Zero)
                return "";
            int len = 0;
            while (System.Runtime.InteropServices.Marshal.ReadByte(ptr, len) != 0)
                len++;
            if (len == 0)
                return "";
            byte[] array = new byte[len];
            System.Runtime.InteropServices.Marshal.Copy(ptr, array, 0, len);
            return System.Text.Encoding.UTF8.GetString(array);
        }

        #region TestDll.dll
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int del_testdll_write2console([MarshalAs(UnmanagedType.LPStr)] string strMsg);  //[MarshalAs(UnmanagedType.LPStr)]
        public static del_testdll_write2console testdll_write2console;

        //[DllImport("TestDll.dll", EntryPoint = "write2console", CallingConvention=CallingConvention.Cdecl)] //CharSet=CharSet.Ansi, ExactSpelling=true, SetLastError=true
        //public static extern int write2console([MarshalAs(UnmanagedType.LPStr)] string strMsg);
#endregion

#region libssh2.dll (version 1.9.0.0)
        public const int LIBSSH2_INIT_NO_CRYPTO = 0x0001;

        /* libssh2_session_method_pref() constants */
        public const int LIBSSH2_METHOD_KEX = 0;
        public const int LIBSSH2_METHOD_HOSTKEY = 1;
        public const int LIBSSH2_METHOD_CRYPT_CS = 2;
        public const int LIBSSH2_METHOD_CRYPT_SC = 3;
        public const int LIBSSH2_METHOD_MAC_CS = 4;
        public const int LIBSSH2_METHOD_MAC_SC = 5;
        public const int LIBSSH2_METHOD_COMP_CS = 6;
        public const int LIBSSH2_METHOD_COMP_SC = 7;
        public const int LIBSSH2_METHOD_LANG_CS = 8;
        public const int LIBSSH2_METHOD_LANG_SC = 9;

        [StructLayout(LayoutKind.Sequential)]
        public struct packet_requirev_state_t
        {
            /* time_t */UInt64 start;
        }

        [StructLayout(LayoutKind.Sequential)] /* ,Pack=4 */
        public struct LIBSSH2_USERAUTH_KBDINT_PROMPT
        {
            /* char* */
            IntPtr text;
            public uint length;
            public byte echo;
        }

        [StructLayout(LayoutKind.Sequential)] /* ,Pack=4 */
        public struct LIBSSH2_USERAUTH_KBDINT_RESPONSE
        {
            public /* char* */IntPtr text;
            public uint length;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct list_head
        {
            public /* list_node */IntPtr last;
            public /* list_node */IntPtr first;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct list_node
        {
            public /* list_node */IntPtr next;
            public /* list_node */IntPtr prev;
            public /* list_head */IntPtr head;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct libssh2_channel_data
        {
            /* Identifier */
            public uint id;

            /* Limits and restrictions */
            public uint window_size_initial;
            public uint window_size;
            public uint packet_size;

            /* Set to 1 when CHANNEL_CLOSE / CHANNEL_EOF sent/received */
            public byte close;
            public byte eof;
            public byte extended_data_ignore_mode;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LIBSSH2_CHANNEL
        {
            list_node node;

            /* char * */IntPtr channel_type;
            uint channel_type_len;

            /* channel's program exit status */
            public int exit_status;

            /* channel's program exit signal (without the SIG prefix) */
            /* char* */IntPtr exit_signal;

            public libssh2_channel_data local;
            public libssh2_channel_data remote;
            /* Amount of bytes to be refunded to receive window (but not yet sent) */
            uint adjust_queue;
            /* Data immediately available for reading */
            uint read_avail;

            /* LIBSSH2_SESSION* */IntPtr session;

            /* void* */IntPtr @abstract;
            public LIBSSH2_CHANNEL_CLOSE_FUNC close_cb;

            /* State variables used in libssh2_channel_setenv_ex() */
            /* libssh2_nonblocking_states */int setenv_state;
            /* unsigned char* */IntPtr setenv_packet;
            /* size_t */UIntPtr setenv_packet_len;
            /* unsigned char */IntPtr setenv_local_channel; /* [4]; */
            packet_requirev_state_t setenv_packet_requirev_state;

            /* State variables used in libssh2_channel_request_pty_ex()
               libssh2_channel_request_pty_size_ex() */
            /* libssh2_nonblocking_states */int reqPTY_state;
            /* unsigned char */
            IntPtr reqPTY_packet; /* [41 + 256]; */
            /* size_t */UIntPtr reqPTY_packet_len;
            /* unsigned char */IntPtr reqPTY_local_channel; /* [4]; */
            packet_requirev_state_t reqPTY_packet_requirev_state;

            /* State variables used in libssh2_channel_x11_req_ex() */
            /* libssh2_nonblocking_states */int reqX11_state;
            /* unsigned char* */IntPtr reqX11_packet;
            /* size_t */UIntPtr reqX11_packet_len;
            /* unsigned char */
            IntPtr reqX11_local_channel; /* [4]; */
            packet_requirev_state_t reqX11_packet_requirev_state;

            /* State variables used in libssh2_channel_process_startup() */
            /* libssh2_nonblocking_states */int process_state;
            /* unsigned char* */IntPtr process_packet;
            /* size_t */UIntPtr process_packet_len;
            /* unsigned char */IntPtr process_local_channel; /* [4]; */
            packet_requirev_state_t process_packet_requirev_state;

            /* State variables used in libssh2_channel_flush_ex() */
            /* libssh2_nonblocking_states */int flush_state;
            /* size_t */UIntPtr flush_refund_bytes;
            /* size_t */UIntPtr flush_flush_bytes;

            /* State variables used in libssh2_channel_receive_window_adjust() */
            /* libssh2_nonblocking_states */int adjust_state;
            /* unsigned char */
            IntPtr adjust_adjust; /* [9]; */     /* packet_type(1) + channel(4) + adjustment(4) */

            /* State variables used in libssh2_channel_read_ex() */
            /* libssh2_nonblocking_states */int read_state;

            uint read_local_id;

            /* State variables used in libssh2_channel_write_ex() */
            /* libssh2_nonblocking_states */int write_state;
            /* unsigned char */IntPtr write_packet; /* [13]; */
            /* size_t */UIntPtr write_packet_len;
            /* size_t */UIntPtr write_bufwrite;

            /* State variables used in libssh2_channel_close() */
            /* libssh2_nonblocking_states */int close_state;
            /* unsigned char */IntPtr close_packet; /* [5]; */

            /* State variables used in libssh2_channel_wait_closedeof() */
            /* libssh2_nonblocking_states */int wait_eof_state;

            /* State variables used in libssh2_channel_wait_closed() */
            /* libssh2_nonblocking_states */int wait_closed_state;

            /* State variables used in libssh2_channel_free() */
            /* libssh2_nonblocking_states */int free_state;

            /* State variables used in libssh2_channel_handle_extended_data2() */
            /* libssh2_nonblocking_states */int extData2_state;

            /* State variables used in libssh2_channel_request_auth_agent() */
            /* libssh2_nonblocking_states */int req_auth_agent_try_state;
            /* libssh2_nonblocking_states */int req_auth_agent_state;
            /* unsigned char */IntPtr req_auth_agent_packet; /* [36]; */
            /* size_t */UIntPtr req_auth_agent_packet_len;
            /* unsigned char */IntPtr req_auth_agent_local_channel; /* [4]; */
            packet_requirev_state_t req_auth_agent_requirev_state;
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate IntPtr del_AllocFunc(/* size_t */ UIntPtr count, IntPtr @abstract);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void del_FreeFunc([In, Out]IntPtr buffer, IntPtr @abstract);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate IntPtr del_ReAllocFunc([In, Out]IntPtr buffer,/* size_t */ UIntPtr count, IntPtr @abstract);

        private static del_AllocFunc AllocFunc = l_AllocFunc;
        private static del_FreeFunc FreeFunc = l_FreeFunc;
        private static del_ReAllocFunc ReAllocFunc = l_ReAllocFunc;

        public static IntPtr l_AllocFunc(/* size_t */ UIntPtr count, IntPtr @abstract)
        {
            return(Marshal.AllocHGlobal((int)count ));  // (count.ToUInt64())
        }
        //[HandleProcessCorruptedStateExceptions]
        //[HandleProcessCorruptedStateExceptionsAttribute]
        public static void l_FreeFunc(IntPtr buffer, IntPtr @abstract)
        {
            if (buffer != IntPtr.Zero)
            {
                //try
                //{
                    Marshal.FreeHGlobal(buffer);
                    buffer = IntPtr.Zero;
                //}catch(Exception ex) { }
            }
            return;
        }
        public static IntPtr l_ReAllocFunc(IntPtr buffer, UIntPtr count, IntPtr @abstract)
        {
            return (Marshal.ReAllocHGlobal(buffer, (IntPtr)((uint)count)));
        }

        public static IntPtr libssh2_session_init()
        {
            return(libssh2_session_init(false));
        }
        public static IntPtr libssh2_session_init(bool WithOwnAlloc)
        {
            if (WithOwnAlloc)
            {
                return (libssh2_session_init_ex(Marshal.GetFunctionPointerForDelegate<del_AllocFunc>(AllocFunc),
                    Marshal.GetFunctionPointerForDelegate<del_FreeFunc>(FreeFunc),
                    Marshal.GetFunctionPointerForDelegate<del_ReAllocFunc>(ReAllocFunc),
                    IntPtr.Zero));
            } else
            {
                return (libssh2_session_init_ex(IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero));
            }
        }

        //[DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        //  Win-Version
        //public static extern int libssh2_session_handshake(IntPtr session, IntPtr sock);
        //  Linux-/MAC-Version
        //public static extern int libssh2_session_handshake(IntPtr session, int sock);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int libssh2_session_handshake_win(IntPtr session, IntPtr sock);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int libssh2_session_handshake_linux(IntPtr session, int sock);

        public static libssh2_session_handshake_linux libssh2_session_handshake_l;
        public static libssh2_session_handshake_win libssh2_session_handshake_w;
        public static int libssh2_session_handshake_all(IntPtr session, IntPtr hSocket, int iSocket)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (hSocket == IntPtr.Zero)
                    return (-1);

                return (libssh2_session_handshake_w(session, hSocket));
            }
            else
            {
                if (iSocket == 0)
                    return (-1);

                return (libssh2_session_handshake_l(session, iSocket));
            }
        }

        public const int LIBSSH2_SESSION_BLOCK_INBOUND = 0x0001;
        public const int LIBSSH2_SESSION_BLOCK_OUTBOUND = 0x0002;

        public const int LIBSSH2_CHANNEL_WINDOW_DEFAULT = 2 * 1024 * 1024;
        public const int LIBSSH2_CHANNEL_PACKET_DEFAULT = 32768;
        public const int LIBSSH2_CHANNEL_MINADJUST = 1024;

        public static int libssh2Init(int minVersion)
        {
            if (libSSH2Init)
                return (0);

            int _rc = libssh2_init(minVersion);
            if(_rc == 0)
                libSSH2Init = true;
            return (_rc);
        }
        public static void libssh2Exit()
        {
            libssh2_exit();
            libSSH2Init = false;
        }

        public static IntPtr libssh2_channel_open_session(IntPtr session)
        {
            const string channelType = "session";
            return libssh2_channel_open_ex(session, channelType, (uint)channelType.Length, LIBSSH2_CHANNEL_WINDOW_DEFAULT, LIBSSH2_CHANNEL_PACKET_DEFAULT, null, 0);
        }

        public static int libssh2_channel_setenv(IntPtr channel, string varname, string value)
        {
            return libssh2_channel_setenv_ex(channel, varname, (uint)varname.Length, value, (uint)value.Length);
        }

        public static int libssh2_channel_shell(IntPtr channel)
        {
            const string request = "shell";
            return libssh2_channel_process_startup(channel, request, (uint)request.Length, null, 0);
        }

        public static int libssh2_channel_exec(IntPtr channel, string command)
        {
            const string request = "exec";
            return libssh2_channel_process_startup(channel, request, (uint)request.Length, command, (uint)command.Length);
        }

        public static int libssh2_channel_subsystem(IntPtr channel, string subsystem)
        {
            const string request = "subsystem";
            return libssh2_channel_process_startup(channel, request, (uint)request.Length, subsystem, (uint)subsystem.Length);
        }

        public static int libssh2_channel_read(IntPtr channel, ref byte[] buf)
        {
            return(libssh2_channel_read_ex(channel, 0, buf, new UIntPtr((uint)buf.Length)));
        }
        /* public static int libssh2_channel_read(IntPtr channel, out IntPtr buf, int bufLen)
        {
            return libssh2_channel_read_ex(channel, 0, out buf, new UIntPtr((uint)bufLen));
        } */

        public const int SSH_EXTENDED_DATA_STDERR = 1;

        public static int libssh2_channel_read_stderr(IntPtr channel,
                                                      byte[] buf)
        {
            return libssh2_channel_read_ex(channel, SSH_EXTENDED_DATA_STDERR, buf, new UIntPtr((uint)buf.Length));
        }

        public static int libssh2_channel_write(IntPtr channel, byte[] buf)
        {
            return libssh2_channel_write_ex(channel, 0, buf, new UIntPtr((uint)buf.Length));
        }
        /* public static int libssh2_channel_write(IntPtr channel, IntPtr buf, int bufLen)
        {
            return libssh2_channel_write_ex(channel, 0, buf, new UIntPtr((uint)bufLen));
        } */

        public static int libssh2_userauth_password(IntPtr session, string username, string password)
        {
            return libssh2_userauth_password_ex(session, username, (uint)username.Length, password, (uint)password.Length, IntPtr.Zero);
        }

        public const int LIBSSH2_TERM_WIDTH = 80;
        public const int LIBSSH2_TERM_HEIGHT = 24;
        public const int LIBSSH2_TERM_WIDTH_PX = 0;
        public const int LIBSSH2_TERM_HEIGHT_PX = 0;

        public static int libssh2_channel_request_pty(IntPtr channel, string term)
        {
            return libssh2_channel_request_pty_ex(channel, term, (uint)term.Length, null, 0,
                                                  LIBSSH2_TERM_WIDTH, LIBSSH2_TERM_HEIGHT,
                                                  LIBSSH2_TERM_WIDTH_PX, LIBSSH2_TERM_HEIGHT_PX);
        }

        public const int SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT = 1;
        public const int SSH_DISCONNECT_PROTOCOL_ERROR = 2;
        public const int SSH_DISCONNECT_KEY_EXCHANGE_FAILED = 3;
        public const int SSH_DISCONNECT_RESERVED = 4;
        public const int SSH_DISCONNECT_MAC_ERROR = 5;
        public const int SSH_DISCONNECT_COMPRESSION_ERROR = 6;
        public const int SSH_DISCONNECT_SERVICE_NOT_AVAILABLE = 7;
        public const int SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED = 8;
        public const int SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE = 9;
        public const int SSH_DISCONNECT_CONNECTION_LOST = 10;
        public const int SSH_DISCONNECT_BY_APPLICATION = 11;
        public const int SSH_DISCONNECT_TOO_MANY_CONNECTIONS = 12;
        public const int SSH_DISCONNECT_AUTH_CANCELLED_BY_USER = 13;
        public const int SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE = 14;
        public const int SSH_DISCONNECT_ILLEGAL_USER_NAME = 15;

        public static int libssh2_session_disconnect(IntPtr session, string description)
        {
            return libssh2_session_disconnect_ex(session, SSH_DISCONNECT_BY_APPLICATION, description, "");
        }

        public const int LIBSSH2_CHANNEL_FLUSH_EXTENDED_DATA = -1;
        public const int LIBSSH2_CHANNEL_FLUSH_ALL = -2;

        public static int libssh2_channel_flush(IntPtr channel)
        {
            return libssh2_channel_flush_ex(channel, 0);
        }

        public static int libssh2_channel_flush_stderr(IntPtr channel)
        {
            return libssh2_channel_flush_ex(channel, SSH_EXTENDED_DATA_STDERR);
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        // IntPtr sig must point to a byte array that has been allocated with malloc()!
        public delegate void LIBSSH2_USERAUTH_KBDINT_RESPONSE_FUNC([MarshalAs(UnmanagedType.LPStr)] string name, int name_len, [MarshalAs(UnmanagedType.LPStr)] string instruction, int instruction_len,
                                                        int num_prompts, ref LIBSSH2_USERAUTH_KBDINT_PROMPT prompts, ref LIBSSH2_USERAUTH_KBDINT_RESPONSE responses, [Out] out IntPtr @abstract);

        public static int libssh2_userauth_keyboard_interactive(IntPtr session, [MarshalAs(UnmanagedType.LPStr)] string username, LIBSSH2_USERAUTH_KBDINT_RESPONSE_FUNC response_callback)
        {
            IntPtr _cbKbInteractive = Marshal.GetFunctionPointerForDelegate(response_callback);
            return libssh2_userauth_keyboard_interactive_ex(session, username, (uint)username.Length, _cbKbInteractive);
        }

        // Error codes
        public const int LIBSSH2_ERROR_NONE = 0;
        public const int LIBSSH2_ERROR_SOCKET_NONE = -1;
        public const int LIBSSH2_ERROR_BANNER_RECV = -2;
        public const int LIBSSH2_ERROR_BANNER_SEND = -3;
        public const int LIBSSH2_ERROR_INVALID_MAC = -4;
        public const int LIBSSH2_ERROR_KEX_FAILURE = -5;
        public const int LIBSSH2_ERROR_ALLOC = -6;
        public const int LIBSSH2_ERROR_SOCKET_SEND = -7;
        public const int LIBSSH2_ERROR_KEY_EXCHANGE_FAILURE = -8;
        public const int LIBSSH2_ERROR_TIMEOUT = -9;
        public const int LIBSSH2_ERROR_HOSTKEY_INIT = -10;
        public const int LIBSSH2_ERROR_HOSTKEY_SIGN = -11;
        public const int LIBSSH2_ERROR_DECRYPT = -12;
        public const int LIBSSH2_ERROR_SOCKET_DISCONNECT = -13;
        public const int LIBSSH2_ERROR_PROTO = -14;
        public const int LIBSSH2_ERROR_PASSWORD_EXPIRED = -15;
        public const int LIBSSH2_ERROR_FILE = -16;
        public const int LIBSSH2_ERROR_METHOD_NONE = -17;
        public const int LIBSSH2_ERROR_AUTHENTICATION_FAILED = -18;
        public const int LIBSSH2_ERROR_PUBLICKEY_UNRECOGNIZED = LIBSSH2_ERROR_AUTHENTICATION_FAILED;
        public const int LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED = -19;
        public const int LIBSSH2_ERROR_CHANNEL_OUTOFORDER = -20;
        public const int LIBSSH2_ERROR_CHANNEL_FAILURE = -21;
        public const int LIBSSH2_ERROR_CHANNEL_REQUEST_DENIED = -22;
        public const int LIBSSH2_ERROR_CHANNEL_UNKNOWN = -23;
        public const int LIBSSH2_ERROR_CHANNEL_WINDOW_EXCEEDED = -24;
        public const int LIBSSH2_ERROR_CHANNEL_PACKET_EXCEEDED = -25;
        public const int LIBSSH2_ERROR_CHANNEL_CLOSED = -26;
        public const int LIBSSH2_ERROR_CHANNEL_EOF_SENT = -27;
        public const int LIBSSH2_ERROR_SCP_PROTOCOL = -28;
        public const int LIBSSH2_ERROR_ZLIB = -29;
        public const int LIBSSH2_ERROR_SOCKET_TIMEOUT = -30;
        public const int LIBSSH2_ERROR_SFTP_PROTOCOL = -31;
        public const int LIBSSH2_ERROR_REQUEST_DENIED = -32;
        public const int LIBSSH2_ERROR_METHOD_NOT_SUPPORTED = -33;
        public const int LIBSSH2_ERROR_INVAL = -34;
        public const int LIBSSH2_ERROR_INVALID_POLL_TYPE = -35;
        public const int LIBSSH2_ERROR_PUBLICKEY_PROTOCOL = -36;
        public const int LIBSSH2_ERROR_EAGAIN = -37;
        public const int LIBSSH2_ERROR_BUFFER_TOO_SMALL = -38;
        public const int LIBSSH2_ERROR_BAD_USE = -39;
        public const int LIBSSH2_ERROR_COMPRESS = -40;
        public const int LIBSSH2_ERROR_OUT_OF_BOUNDARY = -41;
        public const int LIBSSH2_ERROR_AGENT_PROTOCOL = -42;
        public const int LIBSSH2_ERROR_SOCKET_RECV = -43;
        public const int LIBSSH2_ERROR_ENCRYPT = -44;
        public const int LIBSSH2_ERROR_BAD_SOCKET = -45;
        public const int LIBSSH2_ERROR_KNOWN_HOSTS = -46;
        /*
        [DllImport(libSSH2Name, EntryPoint="libssh2_init", CallingConvention = CallingConvention.Cdecl)]
        public static extern int pre_libssh2_init([MarshalAs(UnmanagedType.I4)] int flags);
        [DllImport(libSSH2Name, EntryPoint="libssh2_exit", CallingConvention = CallingConvention.Cdecl)]
        public static extern void pre_libssh2_exit();
        */
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int del_libssh2_init([MarshalAs(UnmanagedType.I4)] int flags);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void del_libssh2_exit();

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void del_libssh2_free(IntPtr session, IntPtr ptr);

        //CharSet = CharSet.Ansi, 
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        /* [return: MarshalAs(UnmanagedType.LPStr)] */
        public delegate IntPtr del_libssh2_version([MarshalAs(UnmanagedType.I4)] int required_version);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate IntPtr del_libssh2_session_init_ex(IntPtr alloc_func, IntPtr free_func, IntPtr realloc_func, IntPtr @abstract);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void del_libssh2_session_set_blocking(IntPtr session, int blocking);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int del_libssh2_session_get_blocking(IntPtr session);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int del_libssh2_session_block_directions(IntPtr session);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int del_libssh2_session_flag(IntPtr session, int flag, int value);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void del_libssh2_keepalive_config(IntPtr session, int want_reply, uint interval);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int del_libssh2_keepalive_send(IntPtr session, /* int* */ ref int seconds_to_next);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int del_libssh2_session_banner_set(IntPtr session, [MarshalAs(UnmanagedType.LPStr)] string banner);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int del_libssh2_banner_set(IntPtr session, [MarshalAs(UnmanagedType.LPStr)] string banner);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.LPStr)]
        public delegate string del_libssh2_session_banner_get(IntPtr session);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void del_libssh2_trace(IntPtr session, int bitmask);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate IntPtr del_libssh2_channel_open_ex(IntPtr session, [MarshalAs(UnmanagedType.LPStr)] string channel_type, uint channel_type_len, uint window_size, uint packet_size, [MarshalAs(UnmanagedType.LPStr)] string message, uint message_len);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int del_libssh2_session_last_error(IntPtr session, ref IntPtr errmsg, out int errmsg_len, int want_buf = 0 /* don't set to 1 - let libSSH2 manage the errmsg buffer! */);
        //public delegate int del_libssh2_session_last_error(IntPtr session, [MarshalAs(UnmanagedType.LPStr), Out] out string errmsg, out int errmsg_len, int want_buf = 1 /* don't set to 0 - let the CLR manage the errmsg buffer! */);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int del_libssh2_session_last_errno(IntPtr session);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int del_libssh2_session_set_last_error(IntPtr session, int errcode, [MarshalAs(UnmanagedType.LPStr)] string errmsg);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int del_libssh2_channel_setenv_ex(IntPtr channel, [MarshalAs(UnmanagedType.LPStr)] string varname, uint varname_len, [MarshalAs(UnmanagedType.LPStr)] string value, uint value_len);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int del_libssh2_channel_process_startup(IntPtr channel, [MarshalAs(UnmanagedType.LPStr)] string request, uint request_len, [MarshalAs(UnmanagedType.LPStr)] string message, uint message_len);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int del_libssh2_channel_read_ex(IntPtr channel, int stream_id, [In, Out] byte[] buf, UIntPtr buflen);
        //public delegate int del_libssh2_channel_read_ex(IntPtr channel, int stream_id, out IntPtr buf, UIntPtr buflen);
        //public delegate int del_libssh2_channel_read_ex(IntPtr channel, int stream_id, [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 3), In, Out] byte[] buf, UIntPtr buflen);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int del_libssh2_channel_get_exit_status(IntPtr channel);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int del_libssh2_channel_request_pty_ex(IntPtr channel, [MarshalAs(UnmanagedType.LPStr)] string term, uint term_len, [MarshalAs(UnmanagedType.LPStr)] string modes, uint modes_len, int width, int height, int width_px, int height_px);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int del_libssh2_channel_send_eof(IntPtr channel);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int del_libssh2_channel_eof(IntPtr channel);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int del_libssh2_channel_wait_eof(IntPtr channel);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int del_libssh2_channel_close(IntPtr channel);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int del_libssh2_channel_wait_closed(IntPtr channel);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int del_libssh2_channel_free(IntPtr channel);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int del_libssh2_session_disconnect_ex(IntPtr session, int reason, [MarshalAs(UnmanagedType.LPStr)] string description, [MarshalAs(UnmanagedType.LPStr)] string lang);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int del_libssh2_session_free(IntPtr session);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.LPStr)]
        public delegate string del_libssh2_hostkey_hash(IntPtr session, int hash_type);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.LPStr)]
        public delegate string del_libssh2_session_hostkey(IntPtr session, [Out] out UIntPtr len, [Out] out int type);

        public static string[] libssh2_session_supported_algos(IntPtr session, int method_type)
        {
            //GCHandle.AddrOfPinnedObject
            string[] resultAlgos = null;
            IntPtr algos = IntPtr.Zero;
            IntPtr pTmpAlgo = IntPtr.Zero;
            int rc = libssh2_session_supported_algs(session, method_type, out algos);
            if(rc > 0)
            {
                resultAlgos = new string[rc];
                unsafe
                {
                    void** pAlgo = (void**)algos.ToPointer();
                    for (int a = 0; a < rc; a++)
                    {
                        pTmpAlgo = (IntPtr)(pAlgo[a]);
                        resultAlgos[a] = Marshal.PtrToStringAnsi(pTmpAlgo);
                    }
                }
                libssh2_free(session, algos);
            }
            return (resultAlgos);
        }
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int del_libssh2_session_supported_algs(IntPtr session, int method_type, [Out] out IntPtr algos);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int del_libssh2_session_method_pref(IntPtr session, int method_type, [MarshalAs(UnmanagedType.LPStr)] string prefs);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate IntPtr del_libssh2_session_methods(IntPtr session, int method_type);
        //[return: MarshalAs(UnmanagedType.LPStr)]
        //public delegate string del_libssh2_session_methods(IntPtr session, int method_type);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int del_libssh2_channel_flush_ex(IntPtr channel, int streamid);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int del_libssh2_channel_write_ex(IntPtr channel, int stream_id, [In] byte[] buf, UIntPtr buflen);
        //public delegate int del_libssh2_channel_write_ex(IntPtr channel, int stream_id, IntPtr buf, UIntPtr buflen);
        //public delegate int del_libssh2_channel_write_ex(IntPtr channel, int stream_id, [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 3), In] byte[] buf, UIntPtr buflen);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int del_libssh2_userauth_password_ex(IntPtr session, [MarshalAs(UnmanagedType.LPStr)] string username, uint username_len, [MarshalAs(UnmanagedType.LPStr)] string password, uint password_len, IntPtr passwotd_change_cb);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate IntPtr del_libssh2_userauth_list(IntPtr session, [MarshalAs(UnmanagedType.LPStr)] string username, uint username_len);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int del_libssh2_userauth_authenticated(IntPtr session);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int del_libssh2_userauth_keyboard_interactive_ex(/* LIBSSH2_SESSION* */IntPtr session, /* const char* */[MarshalAs(UnmanagedType.LPStr)] string username, uint username_len, /* LIBSSH2_USERAUTH_KBDINT_RESPONSE_FUNC */IntPtr response_callback);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int del_libssh2_userauth_publickey_fromfile_ex(IntPtr session, [MarshalAs(UnmanagedType.LPStr)] string username, uint username_len, [MarshalAs(UnmanagedType.LPStr)] string publickey, [MarshalAs(UnmanagedType.LPStr)] string privatekey, [MarshalAs(UnmanagedType.LPStr)] string passphrase);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int del_libssh2_userauth_publickey(IntPtr session, [MarshalAs(UnmanagedType.LPStr)] string username, byte[] pubkeydata, UIntPtr pubkeydata_len, LIBSSH2_USERAUTH_PUBLICKEY_SIGN_FUNC sign_callback, [Out] out IntPtr @abstract);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int del_libssh2_userauth_hostbased_fromfile_ex(IntPtr session, [MarshalAs(UnmanagedType.LPStr)] string username, uint username_len, [MarshalAs(UnmanagedType.LPStr)] string publickey, [MarshalAs(UnmanagedType.LPStr)] string privatekey, [MarshalAs(UnmanagedType.LPStr)] string passphrase, [MarshalAs(UnmanagedType.LPStr)] string hostname, uint hostname_len, [MarshalAs(UnmanagedType.LPStr)] string local_username, uint local_username_len);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int del_libssh2_userauth_publickey_frommemory(IntPtr session, [MarshalAs(UnmanagedType.LPStr)] string username, UIntPtr username_len, [MarshalAs(UnmanagedType.LPStr)] string publickeyfiledata, UIntPtr publickeyfiledata_len, [MarshalAs(UnmanagedType.LPStr)] string privatekeyfiledata, UIntPtr privatekeyfiledata_len, [MarshalAs(UnmanagedType.LPStr)] string passphrase);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void LIBSSH2_CHANNEL_CLOSE_FUNC(IntPtr session, IntPtr session_abstract, IntPtr channel, IntPtr channel_abstract);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] // IntPtr sig must point to a byte array that has been allocated with malloc()!
        public delegate int LIBSSH2_USERAUTH_PUBLICKEY_SIGN_FUNC(IntPtr session, [Out] out IntPtr sig, [Out] out UIntPtr sig_len,
                                                          [In, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 4)] byte[] data, UIntPtr data_len, [Out] out IntPtr @abstract);

        public static int libssh2_userauth_publickey_fromfile(IntPtr session,
                                                                     [MarshalAs(UnmanagedType.LPStr)] string username,
                                                                     [MarshalAs(UnmanagedType.LPStr)] string publickey,
                                                                     [MarshalAs(UnmanagedType.LPStr)] string privatekey,
                                                                     [MarshalAs(UnmanagedType.LPStr)] string passphrase)
        {
            return libssh2_userauth_publickey_fromfile_ex(session, username, (uint)username.Length, publickey, privatekey, passphrase);
        }

        public static del_libssh2_init libssh2_init;
        public static del_libssh2_exit libssh2_exit;
        public static del_libssh2_free libssh2_free;
        public static del_libssh2_version libssh2_version;
        public static del_libssh2_session_init_ex libssh2_session_init_ex;
        public static del_libssh2_session_set_blocking libssh2_session_set_blocking;
        public static del_libssh2_session_get_blocking libssh2_session_get_blocking;
        public static del_libssh2_session_block_directions libssh2_session_block_directions;
        public static del_libssh2_session_flag libssh2_session_flag;
        public static del_libssh2_keepalive_config libssh2_keepalive_config;
        public static del_libssh2_keepalive_send libssh2_keepalive_send;
        public static del_libssh2_session_banner_set libssh2_session_banner_set;
        public static del_libssh2_banner_set libssh2_banner_set;
        public static del_libssh2_session_banner_get libssh2_session_banner_get;
        public static del_libssh2_trace libssh2_trace;
        public static del_libssh2_channel_open_ex libssh2_channel_open_ex;
        public static del_libssh2_session_last_error libssh2_session_last_error;
        public static del_libssh2_session_last_errno libssh2_session_last_errno;
        public static del_libssh2_session_set_last_error libssh2_session_set_last_error;
        public static del_libssh2_channel_setenv_ex libssh2_channel_setenv_ex;
        public static del_libssh2_channel_process_startup libssh2_channel_process_startup;
        public static del_libssh2_channel_read_ex libssh2_channel_read_ex;
        public static del_libssh2_channel_get_exit_status libssh2_channel_get_exit_status;
        public static del_libssh2_channel_request_pty_ex libssh2_channel_request_pty_ex;
        public static del_libssh2_channel_send_eof libssh2_channel_send_eof;
        public static del_libssh2_channel_eof libssh2_channel_eof;
        public static del_libssh2_channel_wait_eof libssh2_channel_wait_eof;
        public static del_libssh2_channel_close libssh2_channel_close;
        public static del_libssh2_channel_wait_closed libssh2_channel_wait_closed;
        public static del_libssh2_channel_free libssh2_channel_free;
        public static del_libssh2_session_disconnect_ex libssh2_session_disconnect_ex;
        public static del_libssh2_session_free libssh2_session_free;
        public static del_libssh2_hostkey_hash libssh2_hostkey_hash;
        public static del_libssh2_session_hostkey libssh2_session_hostkey;
        public static del_libssh2_session_supported_algs libssh2_session_supported_algs;
        public static del_libssh2_session_method_pref libssh2_session_method_pref;
        public static del_libssh2_session_methods libssh2_session_methods;
        public static del_libssh2_channel_flush_ex libssh2_channel_flush_ex;
        public static del_libssh2_channel_write_ex libssh2_channel_write_ex;
        public static del_libssh2_userauth_password_ex libssh2_userauth_password_ex;
        public static del_libssh2_userauth_list libssh2_userauth_list;
        public static del_libssh2_userauth_authenticated libssh2_userauth_authenticated;
        public static del_libssh2_userauth_keyboard_interactive_ex libssh2_userauth_keyboard_interactive_ex;
        public static del_libssh2_userauth_publickey_fromfile_ex libssh2_userauth_publickey_fromfile_ex;
        public static del_libssh2_userauth_publickey libssh2_userauth_publickey;
        public static del_libssh2_userauth_hostbased_fromfile_ex libssh2_userauth_hostbased_fromfile_ex;
        public static del_libssh2_userauth_publickey_frommemory libssh2_userauth_publickey_frommemory;

        /*
[DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
public static extern int libssh2_init([MarshalAs(UnmanagedType.I4)] int flags);

[DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
public static extern void libssh2_exit();

//CharSet = CharSet.Ansi, 
[DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
//[return: MarshalAs(UnmanagedType.LPStr)]
public static extern IntPtr libssh2_version([MarshalAs(UnmanagedType.I4)] int required_version);

[DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
public static extern IntPtr libssh2_session_init_ex(IntPtr alloc_func, IntPtr free_func, IntPtr realloc_func, IntPtr @abstract);

[DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
public static extern void libssh2_session_set_blocking(IntPtr session, int blocking);

[DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
public static extern int libssh2_session_get_blocking(IntPtr session);

[DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
public static extern int libssh2_session_block_directions(IntPtr session);

[DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
public static extern int libssh2_session_flag(IntPtr session, int flag, int value);

[DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
public static extern void libssh2_keepalive_config(IntPtr session, int want_reply, uint interval);

[DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
public static extern int libssh2_keepalive_send(IntPtr session, ref int seconds_to_next);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_session_banner_set(IntPtr session,
                                                            [MarshalAs(UnmanagedType.LPStr)] string banner);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_banner_set(IntPtr session,
                                                    [MarshalAs(UnmanagedType.LPStr)] string banner);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.LPStr)]
        public static extern string libssh2_session_banner_get(IntPtr session);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern void libssh2_trace(IntPtr session, int bitmask);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr libssh2_channel_open_ex(IntPtr session,
                                                            [MarshalAs(UnmanagedType.LPStr)] string channel_type,
                                                            uint channel_type_len,
                                                            uint window_size,
                                                            uint packet_size,
                                                            [MarshalAs(UnmanagedType.LPStr)] string message,
                                                            uint message_len);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_session_last_error(IntPtr session,
                                                            [MarshalAs(UnmanagedType.LPStr), Out] out string errmsg,
                                                            out int errmsg_len,
                                                            int want_buf = 1); // don't set to 0 - let the CLR manage the errmsg buffer!

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_session_last_errno(IntPtr session);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_session_set_last_error(IntPtr session,
                                                                int errcode,
                                                                [MarshalAs(UnmanagedType.LPStr)] string errmsg);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_channel_setenv_ex(IntPtr channel, [MarshalAs(UnmanagedType.LPStr)] string varname,
                                          uint varname_len,
                                          [MarshalAs(UnmanagedType.LPStr)] string value, uint value_len);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_channel_process_startup(IntPtr channel,
                                                                 [MarshalAs(UnmanagedType.LPStr)] string request,
                                                                 uint request_len,
                                                                 [MarshalAs(UnmanagedType.LPStr)] string message,
                                                                 uint message_len);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_channel_read_ex(IntPtr channel,
                                                         int stream_id,
                                                         [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 3), In, Out] byte[] buf,
                                                         UIntPtr buflen);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_channel_get_exit_status(IntPtr channel);


        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_channel_request_pty_ex(IntPtr channel,
                                                                [MarshalAs(UnmanagedType.LPStr)] string term,
                                                                uint term_len,
                                                                [MarshalAs(UnmanagedType.LPStr)] string modes,
                                                                uint modes_len,
                                                                int width,
                                                                int height,
                                                                int width_px,
                                                                int height_px);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_channel_send_eof(IntPtr channel);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_channel_eof(IntPtr channel);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_channel_wait_eof(IntPtr channel);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_channel_close(IntPtr channel);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_channel_wait_closed(IntPtr channel);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void LIBSSH2_CHANNEL_CLOSE_FUNC(IntPtr session, IntPtr session_abstract, IntPtr channel, IntPtr channel_abstract);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_channel_free(IntPtr channel);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_session_disconnect_ex(IntPtr session,
                                                               int reason,
                                                               [MarshalAs(UnmanagedType.LPStr)] string description,
                                                               [MarshalAs(UnmanagedType.LPStr)] string lang);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_session_free(IntPtr session);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.LPStr)]
        public static extern string libssh2_hostkey_hash(IntPtr session, int hash_type);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.LPStr)]
        public static extern string libssh2_session_hostkey(IntPtr session,
                                                            [Out] out UIntPtr len, [Out] out int type);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_session_method_pref(IntPtr session,
                                                             int method_type,
                                                             [MarshalAs(UnmanagedType.LPStr)] string prefs);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.LPStr)]
        public static extern string libssh2_session_methods(IntPtr session, int method_type);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_channel_flush_ex(IntPtr channel, int streamid);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_channel_write_ex(IntPtr channel,
                                                          int stream_id,
                                                          [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 3), In] byte[] buf,
                                                          UIntPtr buflen);

        public static int libssh2_channel_write(IntPtr channel, byte[] buf)
        {
            return libssh2_channel_write_ex(channel, 0, buf, new UIntPtr((uint)buf.Length));
        }

        public static int libssh2_userauth_password(IntPtr session, string username, string password)
        {
            return libssh2_userauth_password_ex(session, username, (uint)username.Length, password, (uint)password.Length, IntPtr.Zero);
        }


        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_userauth_password_ex(IntPtr session,
                                                              [MarshalAs(UnmanagedType.LPStr)] string username,
                                                              uint username_len,
                                                              [MarshalAs(UnmanagedType.LPStr)] string password,
                                                              uint password_len,
                                                              IntPtr passwotd_change_cb);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr libssh2_userauth_list(IntPtr session, [MarshalAs(UnmanagedType.LPStr)] string username, uint username_len);
        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_userauth_authenticated(IntPtr session);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        // IntPtr sig must point to a byte array that has been allocated with malloc()!
        public delegate void LIBSSH2_USERAUTH_KBDINT_RESPONSE_FUNC([MarshalAs(UnmanagedType.LPStr)] string name, int name_len, [MarshalAs(UnmanagedType.LPStr)] string instruction, int instruction_len,
                                                        int num_prompts, ref LIBSSH2_USERAUTH_KBDINT_PROMPT prompts, ref LIBSSH2_USERAUTH_KBDINT_RESPONSE responses, [Out] out IntPtr @abstract);
        //[In, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 4)] byte[] data, UIntPtr data_len
        //void response(const char* name, int name_len, const char* instruction, int instruction_len, int num_prompts, const LIBSSH2_USERAUTH_KBDINT_PROMPT* prompts, LIBSSH2_USERAUTH_KBDINT_RESPONSE *responses, void** abstract);

        public static int libssh2_userauth_keyboard_interactive(IntPtr session, [MarshalAs(UnmanagedType.LPStr)] string username, LIBSSH2_USERAUTH_KBDINT_RESPONSE_FUNC response_callback)
        {
            IntPtr _cbKbInteractive = Marshal.GetFunctionPointerForDelegate(response_callback);
            return libssh2_userauth_keyboard_interactive_ex(session, username, (uint)username.Length, _cbKbInteractive);
        }

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_userauth_keyboard_interactive_ex(IntPtr session, [MarshalAs(UnmanagedType.LPStr)] string username, uint username_len, IntPtr response_callback);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_userauth_publickey_fromfile_ex(IntPtr session,
                                                                        [MarshalAs(UnmanagedType.LPStr)] string username,
                                                                        uint username_len,
                                                                        [MarshalAs(UnmanagedType.LPStr)] string publickey,
                                                                        [MarshalAs(UnmanagedType.LPStr)] string privatekey,
                                                                        [MarshalAs(UnmanagedType.LPStr)] string passphrase);

        public static int libssh2_userauth_publickey_fromfile(IntPtr session,
                                                                     [MarshalAs(UnmanagedType.LPStr)] string username,
                                                                     [MarshalAs(UnmanagedType.LPStr)] string publickey,
                                                                     [MarshalAs(UnmanagedType.LPStr)] string privatekey,
                                                                     [MarshalAs(UnmanagedType.LPStr)] string passphrase)
        {
            return libssh2_userauth_publickey_fromfile_ex(session, username, (uint)username.Length, publickey, privatekey, passphrase);
        }


        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        // IntPtr sig must point to a byte array that has been allocated with malloc()!
        public delegate int LIBSSH2_USERAUTH_PUBLICKEY_SIGN_FUNC(IntPtr session, [Out] out IntPtr sig, [Out] out UIntPtr sig_len,
                                                          [In, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 4)] byte[] data, UIntPtr data_len, [Out] out IntPtr @abstract);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_userauth_publickey(IntPtr session,
                                                            [MarshalAs(UnmanagedType.LPStr)] string username,
                                                            byte[] pubkeydata,
                                                            UIntPtr pubkeydata_len,
                                                            LIBSSH2_USERAUTH_PUBLICKEY_SIGN_FUNC sign_callback,
                                                            [Out] out IntPtr @abstract);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_userauth_hostbased_fromfile_ex(IntPtr session,
                                                                        [MarshalAs(UnmanagedType.LPStr)] string username,
                                                                        uint username_len,
                                                                        [MarshalAs(UnmanagedType.LPStr)] string publickey,
                                                                        [MarshalAs(UnmanagedType.LPStr)] string privatekey,
                                                                        [MarshalAs(UnmanagedType.LPStr)] string passphrase,
                                                                        [MarshalAs(UnmanagedType.LPStr)] string hostname,
                                                                        uint hostname_len,
                                                                        [MarshalAs(UnmanagedType.LPStr)] string local_username,
                                                                        uint local_username_len);

        public static int libssh2_userauth_hostbased_fromfilex(IntPtr session,
                                                               [MarshalAs(UnmanagedType.LPStr)] string username,
                                                               [MarshalAs(UnmanagedType.LPStr)] string publickey,
                                                               [MarshalAs(UnmanagedType.LPStr)] string privatekey,
                                                               [MarshalAs(UnmanagedType.LPStr)] string passphrase,
                                                               [MarshalAs(UnmanagedType.LPStr)] string hostname,
                                                               [MarshalAs(UnmanagedType.LPStr)] string local_username)
        {
            return libssh2_userauth_hostbased_fromfile_ex(session, username, (uint)username.Length, publickey, privatekey,
                                                          passphrase, hostname, (uint)hostname.Length, local_username,
                                                          (uint)local_username.Length);
        }

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_userauth_publickey_frommemory(IntPtr session,
                                                                       [MarshalAs(UnmanagedType.LPStr)] string username,
                                                                       UIntPtr username_len,
                                                                       [MarshalAs(UnmanagedType.LPStr)] string publickeyfiledata,
                                                                       UIntPtr publickeyfiledata_len,
                                                                       [MarshalAs(UnmanagedType.LPStr)] string privatekeyfiledata,
                                                                       UIntPtr privatekeyfiledata_len,
                                                                       [MarshalAs(UnmanagedType.LPStr)] string passphrase);
        */
#endregion
    }
}
