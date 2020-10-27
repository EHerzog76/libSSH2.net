using System;
using System.Text;
using System.IO;
using System.Security.Permissions;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
using libssh2.core.Interop;
using System.Runtime.CompilerServices;

namespace libssh2.core
{
    [System.Security.SuppressUnmanagedCodeSecurity]
    [System.Security.Permissions.SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
    public unsafe class UnmanagedLibrary
    {
        // flags for dlopen
        const int RTLD_LAZY = 1;
        const int RTLD_GLOBAL = 8;

        readonly string libraryPath;
        readonly IntPtr handle;
        private bool bLibOpen = false;
        private static bool bDebug = false;

        public UnmanagedLibrary(string[] libraryPathAlternatives, bool DebugFlag)
        {
            bDebug = DebugFlag;
            this.libraryPath = FirstValidLibraryPath(libraryPathAlternatives);
            if (bDebug)
            {
                Console.WriteLine("Attempting to load native library \"{0}\"", this.libraryPath);
                //Logger.Debug("Attempting to load native library \"{0}\"", this.libraryPath);
            }
            string loadLibraryErrorDetail = "";

            this.handle = PlatformSpecificLoadLibrary(this.libraryPath, out loadLibraryErrorDetail);
            if (this.handle == IntPtr.Zero)
            {
                throw new IOException(string.Format("Error loading native library \"{0}\". {1}",
                                                    this.libraryPath, loadLibraryErrorDetail));
            }
            else
                bLibOpen = true;
        }
        ~UnmanagedLibrary()
        {
            if (bLibOpen)
                this.Close();
        }

        public void Close()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) )
            {
                if (this.handle != IntPtr.Zero)
                    Windows.FreeLibrary(this.handle);
            } else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                if (InteropRuntimeConfig.IsRunningOnMono)
                {
                    if (this.handle != IntPtr.Zero)
                        Mono.dlclose(this.handle);
                } else if (RuntimeInformation.FrameworkDescription.StartsWith(".NET Core"))
                {
                    if (this.handle != IntPtr.Zero)
                        CoreCLR.dlclose(this.handle);
                }
                else {
                    if (this.handle != IntPtr.Zero)
                        Linux.dlclose(this.handle);
                }
                            
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                if (this.handle != IntPtr.Zero)
                    MacOSX.dlclose(this.handle);
            }
            else
            {
                throw new InvalidOperationException("Unsupported platform.");
            }
            bLibOpen = false;
        }

        /// <summary>
        /// Loads symbol in a platform specific way.
        /// </summary>
        /// <param name="symbolName"></param>
        /// <returns></returns>
        private IntPtr LoadSymbol(string symbolName)
        {
            IntPtr pResult = IntPtr.Zero;

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) /* PlatformApis.IsWindows */
            {
                int ErrCode = 0;
                string errorMsg = "";

                // See http://stackoverflow.com/questions/10473310 for background on this.
                if (Environment.Is64BitProcess) /* PlatformApis.Is64Bit */
                {
                    pResult = Windows.GetProcAddress(this.handle, symbolName);
                    if (pResult == IntPtr.Zero)
                    {
                        ErrCode = Marshal.GetLastWin32Error();
                        errorMsg = Windows.GetLastErrMsg((uint)ErrCode);
                        Console.WriteLine("Error while loading function: " + symbolName + "\n\t" + errorMsg);
                    }
                    return(pResult);
                }
                else
                {
                    // Yes, we could potentially predict the size... but it's a lot simpler to just try
                    // all the candidates. Most functions have a suffix of @0, @4 or @8 so we won't be trying
                    // many options - and if it takes a little bit longer to fail if we've really got the wrong
                    // library, that's not a big problem. This is only called once per function in the native library.
                    symbolName = "_" + symbolName + "@";
                    for (int stackSize = 0; stackSize < 128; stackSize += 4)
                    {
                        pResult = Windows.GetProcAddress(this.handle, symbolName + stackSize);
                        if (pResult != IntPtr.Zero)
                        {
                            return pResult;
                        }
                    }
                    // Fail.
                    return IntPtr.Zero;
                }
            }
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                if (InteropRuntimeConfig.IsRunningOnMono) /* PlatformApis.IsMono */
                {
                    return Mono.dlsym(this.handle, symbolName);
                }
                if (RuntimeInformation.FrameworkDescription.StartsWith(".NET Core")) /* PlatformApis.IsNetCore */
                {
                    return CoreCLR.dlsym(this.handle, symbolName);
                }
                return Linux.dlsym(this.handle, symbolName);
            }
            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))  /* PlatformApis.IsMacOSX */
            {
                return MacOSX.dlsym(this.handle, symbolName);
            }
            throw new InvalidOperationException("Unsupported platform.");
        }

        public T GetNativeMethodDelegate<T>(string methodName)
            where T : class
        {
            var ptr = LoadSymbol(methodName);
            if (ptr == IntPtr.Zero)
            {
                throw new MissingMethodException(string.Format("The native method \"{0}\" does not exist", methodName));
            }
#if NETSTANDARD1_5 || NETSTANDARD2_0 || NETSTANDARD2_1 || NETSTANDARD3_0 || NETSTANDARD3_1
            return Marshal.GetDelegateForFunctionPointer<T>(ptr);  // non-generic version is obsolete
#else
            return Marshal.GetDelegateForFunctionPointer(ptr, typeof(T)) as T;  // generic version not available in .NET45
#endif
        }

        /// <summary>
        /// Loads library in a platform specific way.
        /// </summary>
        private static IntPtr PlatformSpecificLoadLibrary(string libraryPath, out string errorMsg)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) /* PlatformApis.IsWindows */
            {
                GCHandle pLibPath;
                errorMsg = null;
                int ErrCode = 0;
                IntPtr pLib = IntPtr.Zero;
                if (libraryPath.Contains("\\"))
                {
                    string libPath = libraryPath.Substring(0, libraryPath.LastIndexOf("\\"));
                    if (bDebug)
                        Console.WriteLine("Set DLL-Searchpath: " + libPath);

                    /* byte[] utf8LibPath = SSH2Library.UTF16toUTF8(libPath);
                    //utf8LibPath[utf8LibPath.Length - 2] = 0;
                    utf8LibPath[utf8LibPath.Length - 1] = 0;
                    pLibPath = GCHandle.Alloc(utf8LibPath, GCHandleType.Pinned);
                    Windows.SetDllDirectory(pLibPath.AddrOfPinnedObject());
                    pLibPath.Free();
                    */
                    Windows.SetDllDirectory(libPath);
                }

                /* byte[] utf8libraryPath = SSH2Library.UTF16toUTF8(libraryPath);
                utf8libraryPath[utf8libraryPath.Length - 1] = 0;
                pLibPath = GCHandle.Alloc(utf8libraryPath, GCHandleType.Pinned);
                //pLib = Windows.LoadLibrary(pLibPath.AddrOfPinnedObject()); //Marshal.UnsafeAddrOfPinnedArrayElement(pLibPath, 0)
                pLib = Windows.LoadLibraryEx(pLibPath.AddrOfPinnedObject(), IntPtr.Zero, Windows.LOAD_WITH_ALTERED_SEARCH_PATH);
                */
                pLib = Windows.LoadLibraryEx(libraryPath, IntPtr.Zero, Windows.LOAD_WITH_ALTERED_SEARCH_PATH);
                if (pLib == IntPtr.Zero)
                {
                    ErrCode = Marshal.GetLastWin32Error();
                    errorMsg = Windows.GetLastErrMsg((uint)ErrCode);
                    errorMsg = "Error while loading: " + libraryPath + "\n\t" + errorMsg;
                }
                //pLibPath.Free();
                return (pLib);
            }
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                if (InteropRuntimeConfig.IsRunningOnMono)
                {
                    return LoadLibraryPosix(Mono.dlopen, Mono.dlerror, libraryPath, out errorMsg);
                }
                if (RuntimeInformation.FrameworkDescription.StartsWith(".NET Core"))
                {
                    return LoadLibraryPosix(CoreCLR.dlopen, CoreCLR.dlerror, libraryPath, out errorMsg);
                }
                return LoadLibraryPosix(Linux.dlopen, Linux.dlerror, libraryPath, out errorMsg);
            }
            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                return LoadLibraryPosix(MacOSX.dlopen, MacOSX.dlerror, libraryPath, out errorMsg);
            }
            throw new InvalidOperationException("Unsupported platform.");
        }

        private static IntPtr LoadLibraryPosix(Func<string, int, IntPtr> dlopenFunc, Func<IntPtr> dlerrorFunc, string libraryPath, out string errorMsg)
        {
            errorMsg = null;
            IntPtr ret = dlopenFunc(libraryPath, RTLD_GLOBAL + RTLD_LAZY);
            if (ret == IntPtr.Zero)
            {
                errorMsg = Marshal.PtrToStringAnsi(dlerrorFunc());
            }
            return ret;
        }

        public static string FirstValidLibraryPath(string[] libraryPathAlternatives)
        {
            if (libraryPathAlternatives.Length == 0) {
                throw new FileNotFoundException("Error loading native library. libraryPathAlternatives cannot be empty.");
            }

            string libFileName = "";
            string libExt = "";

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                libExt = ".dll";
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                libExt = ".dylib";
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                libExt = ".so";
            else
            {

            }

            foreach (string path in libraryPathAlternatives)
            {
                libFileName = path + libExt;
                if (bDebug)
                    Console.WriteLine("Try Lib-Path: " + libFileName);
                if (File.Exists(libFileName))
                {
                    return libFileName;
                }
            }

            //throw new FileNotFoundException(String.Format("Error loading native library. Not found in any of the possible locations: {0}",
            //        string.Join(",", libraryPathAlternatives)));

            //Return last Path, which should only be the Filename of the Library
            return (libraryPathAlternatives[libraryPathAlternatives.Length-1] + libExt);
        }

        private static class Windows
        {
            public const uint LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR = 0x00000100;
            public const uint LOAD_LIBRARY_SEARCH_DEFAULT_DIRS = 0x00001000;
            public const uint LOAD_LIBRARY_SEARCH_SYSTEM32     = 0x00000800;
            public const uint LOAD_WITH_ALTERED_SEARCH_PATH    = 0x00000008;
            public const uint LOAD_LIBRARY_AS_DATAFILE         = 0x00000002;  //Use it load x86-DLL´s in x64-Application and vica-verse

            const uint FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100;
            const uint FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200;
            const uint FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000;
            const uint FORMAT_MESSAGE_ARGUMENT_ARRAY = 0x00002000;
            const uint FORMAT_MESSAGE_FROM_HMODULE = 0x00000800;
            const uint FORMAT_MESSAGE_FROM_STRING = 0x00000400;

            [DllImport("kernel32.dll")]
            static extern IntPtr LocalFree(IntPtr hMem);

            [DllImport("kernel32.dll")]
            static extern uint FormatMessage(uint dwFlags, IntPtr lpSource,
               uint dwMessageId, uint dwLanguageId, [MarshalAs(UnmanagedType.LPStr), Out] StringBuilder lpBuffer,
               uint nSize, IntPtr Arguments);

            // the version, the sample is built upon:
            [DllImport("Kernel32.dll", SetLastError = true)]
            static extern uint FormatMessage(uint dwFlags, IntPtr lpSource,
               uint dwMessageId, uint dwLanguageId, ref IntPtr lpBuffer,
               uint nSize, IntPtr pArguments);

            // the parameters can also be passed as a string array:
            [DllImport("Kernel32.dll", SetLastError = true)]
            static extern uint FormatMessage(uint dwFlags, IntPtr lpSource,
               uint dwMessageId, uint dwLanguageId, ref IntPtr lpBuffer,
               uint nSize, string[] Arguments);

            // see the sample code
            [DllImport("kernel32.dll", SetLastError = true)]
            static extern uint FormatMessage(uint dwFlags, IntPtr lpSource, uint dwMessageId, uint dwLanguageId, [MarshalAs(UnmanagedType.LPStr), Out] StringBuilder lpBuffer, uint nSize, string[] Arguments);

            [DllImport("kernel32.dll")]
            public static extern uint GetLastError();

            [DllImport("kernel32.dll", EntryPoint = "SetDllDirectoryW", CharSet = CharSet.Unicode, SetLastError = true)]  //CharSet = CharSet.Ansi or CharSet.Unicode
            internal static extern int SetDllDirectory([MarshalAs(UnmanagedType.LPWStr)]string filename);
            //internal static extern int SetDllDirectory(IntPtr filename);

            [DllImport("kernel32.dll", EntryPoint = "LoadLibraryW", CharSet = CharSet.Unicode, SetLastError = true)]  //CharSet = CharSet.Ansi or CharSet.Unicode
            internal static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPWStr)]string filename);
            //internal static extern IntPtr LoadLibrary(IntPtr filename);

            [DllImport("kernel32.dll", EntryPoint="LoadLibraryExW", CharSet=CharSet.Unicode, SetLastError = true)]  //CharSet = CharSet.Ansi or CharSet.Unicode
            internal static extern IntPtr LoadLibraryEx([MarshalAs(UnmanagedType.LPWStr)]string filename, IntPtr handle, long dwFlags);
            //internal static extern IntPtr LoadLibraryEx(IntPtr filename, IntPtr handle, long dwFlags);

            [DllImport("kernel32.dll", SetLastError = true)]
            internal static extern int GetModuleHandleEx(uint dwFlags, [MarshalAs(UnmanagedType.LPWStr)]string lpModuleName, [In, Out] /* HMODULE* */ IntPtr phModule);

            [DllImport("kernel32.dll", SetLastError = true)]
            internal static extern bool FreeLibrary(IntPtr handle);

            [DllImport("kernel32.dll", EntryPoint="GetProcAddress", CharSet=CharSet.Unicode, ExactSpelling = true, SetLastError = true)] //CharSet=CharSet.Ansi, ExactSpelling=true, SetLastError=true
            internal static extern IntPtr GetProcAddress(IntPtr hModule, [MarshalAs(UnmanagedType.LPStr)]string procName);

            public static string GetLastErrMsg(uint nLastError)
            {
                IntPtr lpMsgBuf = IntPtr.Zero;

                uint dwChars = FormatMessage(
                    FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                    IntPtr.Zero,
                    nLastError,
                    0, // Default language
                    ref lpMsgBuf,
                    0,
                    IntPtr.Zero);
                if (dwChars == 0)
                {
                    // Handle the error.
                    //int le = Marshal.GetLastWin32Error();
                    return null;
                }
                string sRet = Marshal.PtrToStringAnsi(lpMsgBuf);

                // Free the buffer.
                lpMsgBuf = LocalFree(lpMsgBuf);
                return sRet;
            }
        }

        private static class Linux
        {
            [DllImport("libdl.so")]
            internal static extern IntPtr dlopen(string filename, int flags);

            [DllImport("libdl.so")]
            internal static extern IntPtr dlerror();

            [DllImport("libdl.so")]
            internal static extern IntPtr dlsym(IntPtr handle, string symbol);

            [DllImport("libdl.so")]
            internal static extern int dlclose(IntPtr handle);
        }

        private static class MacOSX
        {
            [DllImport("libSystem.dylib")]
            internal static extern IntPtr dlopen(string filename, int flags);

            [DllImport("libSystem.dylib")]
            internal static extern IntPtr dlerror();

            [DllImport("libSystem.dylib")]
            internal static extern IntPtr dlsym(IntPtr handle, string symbol);

            [DllImport("libSystem.dylib")]
            internal static extern int dlclose(IntPtr handle);
        }

        /// <summary>
        /// On Linux systems, using dlopen and dlsym results in
        /// DllNotFoundException("libdl.so not found") if libc6-dev
        /// is not installed. As a workaround, we load symbols for
        /// dlopen and dlsym from the current process as on Linux
        /// Mono sure is linked against these symbols.
        /// </summary>
        private static class Mono
        {
            [DllImport("__Internal")]
            internal static extern IntPtr dlopen(string filename, int flags);

            [DllImport("__Internal")]
            internal static extern IntPtr dlerror();

            [DllImport("__Internal")]
            internal static extern IntPtr dlsym(IntPtr handle, string symbol);

            [DllImport("__Internal")]
            internal static extern int dlclose(IntPtr handle);
        }

        /// <summary>
        /// Similarly as for Mono on Linux, we load symbols for
        /// dlopen and dlsym from the "libcoreclr.so",
        /// to avoid the dependency on libc-dev Linux.
        /// </summary>
        private static class CoreCLR
        {
            [DllImport("libcoreclr.so")]
            internal static extern IntPtr dlopen(string filename, int flags);

            [DllImport("libcoreclr.so")]
            internal static extern IntPtr dlerror();

            [DllImport("libcoreclr.so")]
            internal static extern IntPtr dlsym(IntPtr handle, string symbol);

            [DllImport("libcoreclr.so")]
            internal static extern IntPtr dlclose(IntPtr handle);
        }
    }
}
