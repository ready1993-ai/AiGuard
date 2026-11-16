using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class VPNGuardProcessTree
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ProcessEntry
    {
        public uint Size, Usage, ProcessId;
        public UIntPtr DefaultHeap;
        public uint ModuleId, Threads, ParentId;
        public int Priority;
        public uint Flags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string File;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint processId);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool Process32FirstW(IntPtr snapshot, ref ProcessEntry entry);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool Process32NextW(IntPtr snapshot, ref ProcessEntry entry);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);

    public static Dictionary<int, int> Parents()
    {
        var result = new Dictionary<int, int>();
        var snapshot = CreateToolhelp32Snapshot(2, 0);
        if (snapshot == new IntPtr(-1)) throw new System.ComponentModel.Win32Exception();
        try
        {
            var entry = new ProcessEntry();
            entry.Size = (uint)Marshal.SizeOf(typeof(ProcessEntry));
            if (Process32FirstW(snapshot, ref entry))
            {
                do { result[(int)entry.ProcessId] = (int)entry.ParentId; }
                while (Process32NextW(snapshot, ref entry));
            }
        }
        finally { CloseHandle(snapshot); }
        return result;
    }
}
