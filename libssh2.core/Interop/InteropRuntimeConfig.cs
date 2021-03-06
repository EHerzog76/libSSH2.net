﻿using System;
using System.Runtime.InteropServices;

namespace libssh2.core.Interop
{
  public class InteropRuntimeConfig
  {
    internal const string LibraryName = "libssh2";
    internal static readonly bool IsRunningOnMono = Type.GetType("Mono.Runtime") != null;

#pragma warning disable 414
    internal static readonly string ArchitectureDirectory;
#pragma warning restore 414

    static InteropRuntimeConfig()
    {
      switch (RuntimeInformation.ProcessArchitecture)
      {
        case Architecture.X86:
          ArchitectureDirectory = "x86";
          break;
        case Architecture.X64:
          ArchitectureDirectory = "x64";
          break;
        case Architecture.Arm:
          ArchitectureDirectory = "arm";
          break;
        case Architecture.Arm64:
          ArchitectureDirectory = "arm64";
          break;

        default:
          throw new ArgumentOutOfRangeException();
      }
    }
  }
}