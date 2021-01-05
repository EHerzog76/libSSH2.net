# libSSH2.net
This is a wrapper for the libSSH2-library.
It is copiled for NetStandard 2.0, so it is useable on the .net- and .net core-framework.
And it runs on Windows- and Linux-OS (MAC-OS should also work).

## How to use libSSH2.net

### Get version of libssh2-library:
```
  SSH2Library.Open(DebugFlag);
  int rc = SSH2Library.libssh2_init(0);
  if (rc != 0)
  {
    return("Error: Could not open libSSH2 !");
  }

  IntPtr p_LibSSHVer = SSH2Library.libssh2_version(0);
  string libSSHVersion = SSH2Library.PtrToStringUtf8(p_LibSSHVer);
  SSH2Library.libssh2_exit();
  SSH2Library.Close();
```

### Basic usage of libssh2-library:

See in the demo-program: TestSSH->Program.cs

```
  SSH2Library.Open(DebugFlag);
  int rc = SSH2Library.libssh2_init(0);
  if (rc != 0)
  {
    return("Error: Could not open libSSH2 !");
  }

  Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
  s.Connect(addr, dstPort);
  
  libSSHSession = SSH2Library.libssh2_session_init();
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
  
  //Now you can send and receive:
  //
  // rc = SSH2Library.libssh2_channel_write(sshChannel, dataBuffer);
  // recvBytes = SSH2Library.libssh2_channel_read(sshChannel, ref reBuf);
  //
  
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
```


