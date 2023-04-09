using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Text.Json;
using Microsoft.Win32;
using System.Diagnostics;
using System.Security.Principal;

namespace DIDCommKnockKnock
{
    internal class Program
    {
        const string protocolname = "knockknock";
        static void Main(string[] args)
        {
            //string jsonArgs = JsonSerializer.Serialize(args);
            //Console.WriteLine(jsonArgs);
            if (args.Length >= 1)
            {
                if (args[0] == "-register")
                {
                    if (IsAdministrator())
                    {
                        Console.WriteLine("Running As Administrator");
                        if (args.Length >= 2)
                        {
                            if (args[1] == "-force")
                            {
                                bool found = DeleteMyProtocol(protocolname);
                                if (found)
                                    Console.WriteLine(protocolname + " deleted");
                                else
                                    Console.WriteLine(protocolname + " not found");
                            }
                        }
                        RegisterMyProtocol(protocolname);
                        Console.WriteLine(protocolname + " registered");
                    }
                    else
                    {
                        Console.WriteLine(protocolname + " registration failed - use Run As Administrator");
                    }
                }
                else
                {
                    Console.WriteLine(args[0]);
                    Console.WriteLine("-----");

                    string[] parts = args[0].Split('?');
                    Console.WriteLine(parts[0]);
                    if (parts.Length >= 2) Console.WriteLine(parts[1]);
                    Console.WriteLine("-----");

                    string[] subparts = parts[0].Split('/');
                    foreach (string subpart in subparts)
                    {
                        Console.WriteLine(subpart);
                    }
                    Console.WriteLine("-----");

                    if (parts.Length >= 2)
                    {
                        subparts = parts[1].Split('&');
                        foreach (string subpart in subparts)
                        {
                            string[] namevaluepair = subpart.Split('=');
                            string name = namevaluepair[0];
                            string value;
                            if (namevaluepair.Length >= 2) value = namevaluepair[1];
                            else value = "\"\"";
                            Console.WriteLine(name + "=" + value);
                        }
                        Console.WriteLine("-----");
                    }
                }
            }

            Console.WriteLine("Press Enter to exit");
            Console.ReadLine();
        }

        static bool DeleteMyProtocol(string protocolname)
        {
            bool found = false;
            RegistryKey protocolkey = Registry.ClassesRoot.OpenSubKey(protocolname);
            if (protocolkey != null)
            {
                found = true;   
                Registry.ClassesRoot.DeleteSubKeyTree(protocolname, false);
            }
            return found;
        }

        // https://codingvision.net/c-register-a-url-protocol
        static void RegisterMyProtocol(string protocolname)  
        {
            string executablename = Process.GetCurrentProcess().MainModule.FileName;
            RegistryKey subkey = null;

            RegistryKey protocolkey = Registry.ClassesRoot.OpenSubKey(protocolname);
            if (protocolkey == null)
            {
                protocolkey = Registry.ClassesRoot.CreateSubKey(protocolname);
                protocolkey.SetValue(string.Empty, "URL:" + protocolname + " Protocol");
                protocolkey.SetValue("URL Protocol", string.Empty);

                subkey = protocolkey.CreateSubKey(@"DefaultIcon");
                subkey.SetValue(string.Empty, executablename);

                subkey = protocolkey.CreateSubKey(@"shell\open\command");
                subkey.SetValue(string.Empty, executablename + " " + "%1");
            }

            protocolkey.Close();
        }

        // https://stackoverflow.com/questions/11660184/c-sharp-check-if-run-as-administrator
        public static bool IsAdministrator()
        {
            var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
    }
}
