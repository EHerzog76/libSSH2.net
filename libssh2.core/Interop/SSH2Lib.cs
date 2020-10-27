using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
using System.Collections;
using System.Collections.Generic;

namespace libssh2.core.Interop
{
    public static class SSH2Lib
    {
        public static UnmanagedLibrary _libSSH2 = null;
        public static string libSSH2Name = "libssh2";
        public static libSSH2 SSH2Library;

        static SSH2Lib()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                SSH2Library = new libSSH2Win();
            else
                SSH2Library = new libSSH2Linux();
        }

        public static void Open(bool DebugFlag)
        {
            string thisAssemblyPath = new Uri(typeof(SSH2Library).Assembly.CodeBase).LocalPath;
            string thisAssemblyFolder = Path.GetDirectoryName(thisAssemblyPath);
            List<string> libPaths = new List<string>();
            ArrayList libArray = new ArrayList();

            string dllDirectoryPath = Path.Combine(thisAssemblyFolder, "libssh2");
            string vcruntimePath = Path.Combine(dllDirectoryPath, "vcruntime140");
            string libssh2Path = Path.Combine(dllDirectoryPath, "libssh2");
            string zlib1Path = Path.Combine(dllDirectoryPath, "zlib1");

            if (_libSSH2 != null)
                return;

            try
            {
                libPaths.Add(Path.Combine(thisAssemblyFolder, "libssh2"));
                libPaths.Add(libssh2Path);
                libPaths.Add("libssh2");
                libSSH2Name = UnmanagedLibrary.FirstValidLibraryPath(libPaths.ToArray());
                _libSSH2 = new UnmanagedLibrary(libPaths.ToArray(), DebugFlag);
                libPaths.Clear();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: Loading library libssh2 !\n" + ex.Message);
                libPaths.Clear();
            }
        }

        public static void Close()
        {
            if (_libSSH2 != null)
            {
                _libSSH2.Close();
                _libSSH2 = null;
            }
        }
    }

    public class libSSH2
    {
        public const string libSSH2Name = "libssh2";

        public libSSH2()
        {
        }

        public const int LIBSSH2_INIT_NO_CRYPTO = 0x0001;

        public const int LIBSSH2_SESSION_BLOCK_INBOUND = 0x0001;
        public const int LIBSSH2_SESSION_BLOCK_OUTBOUND = 0x0002;

        public const int LIBSSH2_CHANNEL_WINDOW_DEFAULT = 2 * 1024 * 1024;
        public const int LIBSSH2_CHANNEL_PACKET_DEFAULT = 32768;
        public const int LIBSSH2_CHANNEL_MINADJUST = 1024;

        public const int LIBSSH2_TERM_WIDTH = 80;
        public const int LIBSSH2_TERM_HEIGHT = 24;
        public const int LIBSSH2_TERM_WIDTH_PX = 0;
        public const int LIBSSH2_TERM_HEIGHT_PX = 0;

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

        public const int LIBSSH2_CHANNEL_FLUSH_EXTENDED_DATA = -1;
        public const int LIBSSH2_CHANNEL_FLUSH_ALL = -2;

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

        [StructLayout(LayoutKind.Sequential)]
        public struct packet_requirev_state_t
        {
            /* time_t */
            UInt64 start;
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

            /* char * */
            IntPtr channel_type;
            uint channel_type_len;

            /* channel's program exit status */
            public int exit_status;

            /* channel's program exit signal (without the SIG prefix) */
            /* char* */
            IntPtr exit_signal;

            public libssh2_channel_data local;
            public libssh2_channel_data remote;
            /* Amount of bytes to be refunded to receive window (but not yet sent) */
            uint adjust_queue;
            /* Data immediately available for reading */
            uint read_avail;

            /* LIBSSH2_SESSION* */
            IntPtr session;

            /* void* */
            IntPtr @abstract;
            public LIBSSH2_CHANNEL_CLOSE_FUNC close_cb;

            /* State variables used in libssh2_channel_setenv_ex() */
            /* libssh2_nonblocking_states */
            int setenv_state;
            /* unsigned char* */
            IntPtr setenv_packet;
            /* size_t */
            UIntPtr setenv_packet_len;
            /* unsigned char */
            IntPtr setenv_local_channel; /* [4]; */
            packet_requirev_state_t setenv_packet_requirev_state;

            /* State variables used in libssh2_channel_request_pty_ex()
               libssh2_channel_request_pty_size_ex() */
            /* libssh2_nonblocking_states */
            int reqPTY_state;
            /* unsigned char */
            IntPtr reqPTY_packet; /* [41 + 256]; */
            /* size_t */
            UIntPtr reqPTY_packet_len;
            /* unsigned char */
            IntPtr reqPTY_local_channel; /* [4]; */
            packet_requirev_state_t reqPTY_packet_requirev_state;

            /* State variables used in libssh2_channel_x11_req_ex() */
            /* libssh2_nonblocking_states */
            int reqX11_state;
            /* unsigned char* */
            IntPtr reqX11_packet;
            /* size_t */
            UIntPtr reqX11_packet_len;
            /* unsigned char */
            IntPtr reqX11_local_channel; /* [4]; */
            packet_requirev_state_t reqX11_packet_requirev_state;

            /* State variables used in libssh2_channel_process_startup() */
            /* libssh2_nonblocking_states */
            int process_state;
            /* unsigned char* */
            IntPtr process_packet;
            /* size_t */
            UIntPtr process_packet_len;
            /* unsigned char */
            IntPtr process_local_channel; /* [4]; */
            packet_requirev_state_t process_packet_requirev_state;

            /* State variables used in libssh2_channel_flush_ex() */
            /* libssh2_nonblocking_states */
            int flush_state;
            /* size_t */
            UIntPtr flush_refund_bytes;
            /* size_t */
            UIntPtr flush_flush_bytes;

            /* State variables used in libssh2_channel_receive_window_adjust() */
            /* libssh2_nonblocking_states */
            int adjust_state;
            /* unsigned char */
            IntPtr adjust_adjust; /* [9]; */     /* packet_type(1) + channel(4) + adjustment(4) */

            /* State variables used in libssh2_channel_read_ex() */
            /* libssh2_nonblocking_states */
            int read_state;

            uint read_local_id;

            /* State variables used in libssh2_channel_write_ex() */
            /* libssh2_nonblocking_states */
            int write_state;
            /* unsigned char */
            IntPtr write_packet; /* [13]; */
            /* size_t */
            UIntPtr write_packet_len;
            /* size_t */
            UIntPtr write_bufwrite;

            /* State variables used in libssh2_channel_close() */
            /* libssh2_nonblocking_states */
            int close_state;
            /* unsigned char */
            IntPtr close_packet; /* [5]; */

            /* State variables used in libssh2_channel_wait_closedeof() */
            /* libssh2_nonblocking_states */
            int wait_eof_state;

            /* State variables used in libssh2_channel_wait_closed() */
            /* libssh2_nonblocking_states */
            int wait_closed_state;

            /* State variables used in libssh2_channel_free() */
            /* libssh2_nonblocking_states */
            int free_state;

            /* State variables used in libssh2_channel_handle_extended_data2() */
            /* libssh2_nonblocking_states */
            int extData2_state;

            /* State variables used in libssh2_channel_request_auth_agent() */
            /* libssh2_nonblocking_states */
            int req_auth_agent_try_state;
            /* libssh2_nonblocking_states */
            int req_auth_agent_state;
            /* unsigned char */
            IntPtr req_auth_agent_packet; /* [36]; */
            /* size_t */
            UIntPtr req_auth_agent_packet_len;
            /* unsigned char */
            IntPtr req_auth_agent_local_channel; /* [4]; */
            packet_requirev_state_t req_auth_agent_requirev_state;
        }

        //[DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        //  Win-Version
        //public static extern int libssh2_session_handshake(IntPtr session, IntPtr sock);
        //  Linux-/MAC-Version
        //public static extern int libssh2_session_handshake(IntPtr session, int sock);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_init([MarshalAs(UnmanagedType.I4)] int flags);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern void libssh2_exit();

        //CharSet = CharSet.Ansi, 
        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        /* [return: MarshalAs(UnmanagedType.LPStr)] */
        public static extern IntPtr libssh2_version([MarshalAs(UnmanagedType.I4)] int required_version);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr libssh2_session_init_ex(IntPtr alloc_func, IntPtr free_func, IntPtr realloc_func, IntPtr @abstract);

        public static IntPtr libssh2_session_init() => libssh2_session_init_ex(IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);

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
        public static extern int libssh2_keepalive_send(IntPtr session, /* int* */ ref int seconds_to_next);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_session_banner_set(IntPtr session, [MarshalAs(UnmanagedType.LPStr)] string banner);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_banner_set(IntPtr session, [MarshalAs(UnmanagedType.LPStr)] string banner);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.LPStr)]
        public static extern string libssh2_session_banner_get(IntPtr session);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern void libssh2_trace(IntPtr session, int bitmask);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr libssh2_channel_open_ex(IntPtr session, [MarshalAs(UnmanagedType.LPStr)] string channel_type, uint channel_type_len, uint window_size, uint packet_size, [MarshalAs(UnmanagedType.LPStr)] string message, uint message_len);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_session_last_error(IntPtr session, [MarshalAs(UnmanagedType.LPStr), Out] out string errmsg, out int errmsg_len, int want_buf = 1 /* don't set to 0 - let the CLR manage the errmsg buffer! */);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_session_last_errno(IntPtr session);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_session_set_last_error(IntPtr session, int errcode, [MarshalAs(UnmanagedType.LPStr)] string errmsg);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_channel_setenv_ex(IntPtr channel, [MarshalAs(UnmanagedType.LPStr)] string varname, uint varname_len, [MarshalAs(UnmanagedType.LPStr)] string value, uint value_len);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_channel_process_startup(IntPtr channel, [MarshalAs(UnmanagedType.LPStr)] string request, uint request_len, [MarshalAs(UnmanagedType.LPStr)] string message, uint message_len);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_channel_read_ex(IntPtr channel, int stream_id, [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 3), In, Out] byte[] buf, UIntPtr buflen);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_channel_get_exit_status(IntPtr channel);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_channel_request_pty_ex(IntPtr channel, [MarshalAs(UnmanagedType.LPStr)] string term, uint term_len, [MarshalAs(UnmanagedType.LPStr)] string modes, uint modes_len, int width, int height, int width_px, int height_px);

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

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_channel_free(IntPtr channel);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_session_disconnect_ex(IntPtr session, int reason, [MarshalAs(UnmanagedType.LPStr)] string description, [MarshalAs(UnmanagedType.LPStr)] string lang);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_session_free(IntPtr session);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.LPStr)]
        public static extern string libssh2_hostkey_hash(IntPtr session, int hash_type);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.LPStr)]
        public static extern string libssh2_session_hostkey(IntPtr session, [Out] out UIntPtr len, [Out] out int type);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_session_method_pref(IntPtr session, int method_type, [MarshalAs(UnmanagedType.LPStr)] string prefs);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.LPStr)]
        public static extern string libssh2_session_methods(IntPtr session, int method_type);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_channel_flush_ex(IntPtr channel, int streamid);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_channel_write_ex(IntPtr channel, int stream_id, [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 3), In] byte[] buf, UIntPtr buflen);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_userauth_password_ex(IntPtr session, [MarshalAs(UnmanagedType.LPStr)] string username, uint username_len, [MarshalAs(UnmanagedType.LPStr)] string password, uint password_len, IntPtr passwotd_change_cb);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr libssh2_userauth_list(IntPtr session, [MarshalAs(UnmanagedType.LPStr)] string username, uint username_len);
        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_userauth_authenticated(IntPtr session);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_userauth_keyboard_interactive_ex(/* LIBSSH2_SESSION* */IntPtr session, /* const char* */[MarshalAs(UnmanagedType.LPStr)] string username, uint username_len, /* LIBSSH2_USERAUTH_KBDINT_RESPONSE_FUNC */IntPtr response_callback);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_userauth_publickey_fromfile_ex(IntPtr session, [MarshalAs(UnmanagedType.LPStr)] string username, uint username_len, [MarshalAs(UnmanagedType.LPStr)] string publickey, [MarshalAs(UnmanagedType.LPStr)] string privatekey, [MarshalAs(UnmanagedType.LPStr)] string passphrase);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_userauth_publickey(IntPtr session, [MarshalAs(UnmanagedType.LPStr)] string username, byte[] pubkeydata, UIntPtr pubkeydata_len, LIBSSH2_USERAUTH_PUBLICKEY_SIGN_FUNC sign_callback, [Out] out IntPtr @abstract);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_userauth_hostbased_fromfile_ex(IntPtr session, [MarshalAs(UnmanagedType.LPStr)] string username, uint username_len, [MarshalAs(UnmanagedType.LPStr)] string publickey, [MarshalAs(UnmanagedType.LPStr)] string privatekey, [MarshalAs(UnmanagedType.LPStr)] string passphrase, [MarshalAs(UnmanagedType.LPStr)] string hostname, uint hostname_len, [MarshalAs(UnmanagedType.LPStr)] string local_username, uint local_username_len);

        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_userauth_publickey_frommemory(IntPtr session, [MarshalAs(UnmanagedType.LPStr)] string username, UIntPtr username_len, [MarshalAs(UnmanagedType.LPStr)] string publickeyfiledata, UIntPtr publickeyfiledata_len, [MarshalAs(UnmanagedType.LPStr)] string privatekeyfiledata, UIntPtr privatekeyfiledata_len, [MarshalAs(UnmanagedType.LPStr)] string passphrase);

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
    }

    public class libSSH2Linux : libSSH2
    {
        //  Linux-/MAC-Version
        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_session_handshake(IntPtr session, int sock);
    }
    public class libSSH2Win : libSSH2
    {
        public libSSH2Win()
        {
        }
        //  Win-Version
        [DllImport(libSSH2Name, CallingConvention = CallingConvention.Cdecl)]
        public static extern int libssh2_session_handshake(IntPtr session, IntPtr sock);
    }
}
