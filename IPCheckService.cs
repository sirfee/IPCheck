using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Mail;
using System.ServiceProcess;
using System.Text.RegularExpressions;
using System.Threading;
using System.Xml;

namespace IPCheckService
{
    class IPCheckService : ServiceBase
    {
        /// <summary>

        /// Public Constructor for WindowsService.

        /// - Put all of your Initialization code here.

        /// </summary>
        /// 
        public class CheckSite
        {
            public string HostName { get; set; }
            public string User { get; set; }
            public string Password { get; set; }
            public bool Disabled { get; set; }
            public IPAddress IpAddresses { get; set; }
        }

        public static string _getIPSiteOne;
        public static string _getIPSiteTwo;
        public static int _checkTime;
        public static bool _doLog;
        public static bool _doEmailNotification;
        public static string _emailAddress;
        public static string _smtpAddress;
        public static string _smtpUserName;
        public static string _smtpPassWord;
        public static bool _failedToGetIP;
        public static IPAddress _lastSentIPAddress;
        public static CheckSite[] _sitesToCheck;
        public static IPAddress[] _excludedIPAddresses;
        public static Timer _timer;

        public IPCheckService()
        {
            this.ServiceName = "IPCheck";
            this.EventLog.Log = "Application";

            // These Flags set whether or not to handle that specific

            //  type of event. Set to true if you need it, false otherwise.

            this.CanHandlePowerEvent = true;
            this.CanHandleSessionChangeEvent = true;
            this.CanPauseAndContinue = true;
            this.CanShutdown = true;
            this.CanStop = true;
        }

        /// <summary>

        /// The Main Thread: This is where your Service is Run.

        /// </summary>

        static void Main()
        {
            ServiceBase.Run(new IPCheckService());
        }

        /// <summary>

        /// Dispose of objects that need it here.

        /// </summary>

        /// <param name="disposing">Whether

        ///    or not disposing is going on.</param>

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
        }

        /// <summary>

        /// OnStart(): Put startup code here

        ///  - Start threads, get initial data, etc.

        /// </summary>

        /// <param name="args"></param>

        protected override void OnStart(string[] args)
        {
            LoadConfig();
            int timeInterval = _checkTime;
            TimerCallback timerDelegate = new TimerCallback(CheckIP);
            Timer serviceTimer = new Timer(timerDelegate, null, 5000, timeInterval);
            _timer = serviceTimer;
        }

        private void LoadConfig()
        {
            XmlDocument xmlDocument = new XmlDocument();
            try
            {
                _failedToGetIP = false;
                xmlDocument.Load(@"IPCheck.xml");
                XmlNode root = xmlDocument.SelectSingleNode("Settings");
                XmlNode GlobalSettings = root.SelectSingleNode("GlobalSettings");
                _getIPSiteOne = GlobalSettings.Attributes.GetNamedItem("IPWebSite").Value;
                _getIPSiteTwo = GlobalSettings.Attributes.GetNamedItem("AltIPWebSite").Value;
                _checkTime = 60000 * Convert.ToInt32(GlobalSettings.Attributes.GetNamedItem("CheckTime").Value);
                _doLog = Convert.ToBoolean(Convert.ToInt32(GlobalSettings.Attributes.GetNamedItem("Logging").Value));
                string ips = GlobalSettings.Attributes.GetNamedItem("ExcludeIPs").Value;
                string[] ipAddresses = ips.Split(',');
                _excludedIPAddresses = new IPAddress[ipAddresses.Length];
                int index = 0;
                foreach (string ipAddress in ipAddresses)
                {
                    _excludedIPAddresses[index] = IPAddress.Parse(ipAddress);
                    ++index;
                }

                XmlNode emailSettings = root.SelectSingleNode("EmailSettings");
                _doEmailNotification = Convert.ToBoolean(Convert.ToInt32(emailSettings.Attributes.GetNamedItem("SendEmail").Value));
                _emailAddress = emailSettings.Attributes.GetNamedItem("EmailAddress").Value;
                _smtpAddress = emailSettings.Attributes.GetNamedItem("smtpHost").Value;
                _smtpUserName = emailSettings.Attributes.GetNamedItem("smtpUserName").Value;
                _smtpPassWord = emailSettings.Attributes.GetNamedItem("smtpPassword").Value;
                _lastSentIPAddress = IPAddress.Parse(emailSettings.Attributes.GetNamedItem("CurrentIP").Value);

                XmlNode sites = root.SelectSingleNode("SiteSettings");
                _sitesToCheck = new CheckSite[sites.SelectNodes("Site").Count];
                index = 0;
                foreach (XmlNode site in sites)
                {
                    _sitesToCheck[index] = new CheckSite();
                    _sitesToCheck[index].HostName = site.Attributes.GetNamedItem("Host").Value;
                    _sitesToCheck[index].User = site.Attributes.GetNamedItem("User").Value;
                    _sitesToCheck[index].Password = site.Attributes.GetNamedItem("Password").Value;
                    _sitesToCheck[index].IpAddresses = IPAddress.Parse(site.Attributes.GetNamedItem("IPAddress").Value);
                    _sitesToCheck[index].Disabled = Convert.ToBoolean(Convert.ToInt32(site.Attributes.GetNamedItem("Disabled").Value));
                    ++index;
                }
            }
            catch (Exception exception)
            {
                _doLog = true;
                Log(string.Format("Error loading Configuration : {0}", exception.Message));
            }
        }

        private void CheckIP(object state)
        {
            try
            {
                bool stopChecking = false;
                bool ipfound = false;
                if (!stopChecking)
                {
                    IPAddress externalAddress = GetMyIp();
                    if (externalAddress != IPAddress.None)
                    {
                        if (CheckIpNotExcluded(externalAddress))
                        {
                            stopChecking = true;
                            Log(string.Format("Got IPAddress : {0}", externalAddress));
                            DoUpdate(externalAddress);
                            ipfound = true;
                        }
                    }
                    else
                    {
                        if (!_failedToGetIP)
                        {
                            _failedToGetIP = true;
                            SendFailedGetIPEmail();
                        }
                    }
                }
                if (_failedToGetIP && ipfound)
                {
                    _failedToGetIP = false;
                    SendFailedGetIPEmail();
                }
            }
            catch (Exception exception)
            {
                _failedToGetIP = true;
                SendFailedGetIPEmail();
                EventLog.WriteEntry("Error in IPCheck Service", 
                    exception.ToString(), 
                    EventLogEntryType.Error);
            }
        }

        private void DoUpdate(IPAddress ipAddress)
        {
            try
            {
                foreach (CheckSite site in _sitesToCheck)
                {
                    if (!site.Disabled)
                    {
                        if (!ipAddress.Equals(site.IpAddresses))
                        {
                            string updateString = string.Format(@"https://dyn.dns.he.net/nic/update?hostname={0}", site.HostName);
                            Log(string.Format("Updating site {0} from : {1} To : {2}", site.HostName, site.IpAddresses, ipAddress));
                            if (!UpdateOK(updateString, site.HostName, site.Password))
                            {
                                Log(string.Format("Update failed for site : {0}", site.HostName));
                                site.Disabled = true;
                                DisableConfig(site);
                            }
                            else
                            {
                                Log("Updated OK");
                                site.IpAddresses = ipAddress;
                                UpdateConfig(site);
                            }
                        }
                    }
                    else
                    {
                        //Check Current Ip Against last saved in config sent to email if different send a new email and re update
                        if (!ipAddress.Equals(_lastSentIPAddress))
                        {
                            if (SendEmail(ipAddress, _lastSentIPAddress))
                                UpdateConfigEmailConfig(ipAddress);
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                Log(string.Format("Error checking update : {0}", exception.Message));
            }
        }

        private void UpdateConfigEmailConfig(IPAddress ipAddress)
        {
            XmlDocument xmlDocument = new XmlDocument();
            try
            {
                xmlDocument.Load(@"IPCheck.xml");
                XmlNode root = xmlDocument.SelectSingleNode("Settings");
                XmlNode EmailSettings = root.SelectSingleNode("EmailSettings");
                EmailSettings.Attributes.GetNamedItem("CurrentIP").Value = ipAddress.ToString();
                xmlDocument.Save(@"IPCheck.xml");
            }
            catch (Exception exception)
            {
                Log(string.Format("Error updating Configuration : {0}", exception.Message));
            }
        }

        private bool SendEmail(IPAddress ipAddress, IPAddress oldIpAddress)
        {
            bool result = false;
            if (_doEmailNotification)
            {
                MailMessage message = new MailMessage
                {
                    From = new MailAddress(_emailAddress)
                };
                message.To.Add(new MailAddress(_emailAddress));
                message.Subject = "IPCheck failed to update";
                message.Body = string.Format("Ip check failed to update from address {0} to address {1} at {2} {3}", oldIpAddress, ipAddress, DateTime.Now.ToShortDateString(), DateTime.Now.ToShortTimeString());
                message.IsBodyHtml = true;
                try
                {
                    SmtpClient smtpClient = new SmtpClient();
                    smtpClient.Host = _smtpAddress;
                    smtpClient.Credentials = new System.Net.NetworkCredential
                         (_smtpUserName, _smtpPassWord);
                    smtpClient.EnableSsl = true;
                    smtpClient.Port = 587;
                    smtpClient.Send(message);
                    result = true;
                    _lastSentIPAddress = ipAddress;
                }
                catch (Exception exception)
                {
                    Log(string.Format("Error sending email : {0}", exception.Message));
                    Log(exception.Message);
                }
            }
            return result;
        }

        private void UpdateConfig(CheckSite site)
        {
            XmlDocument xmlDocument = new XmlDocument();
            try
            {
                xmlDocument.Load(@"IPCheck.xml");
                XmlNode root = xmlDocument.SelectSingleNode("Settings");
                XmlNode sites = root.SelectSingleNode("SiteSettings");
                foreach (XmlNode siteNode in sites)
                {
                    if (string.Compare(site.HostName, siteNode.Attributes.GetNamedItem("Host").Value, StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        siteNode.Attributes.GetNamedItem("IPAddress").Value = site.IpAddresses.ToString();
                    }
                }
                xmlDocument.Save(@"IPCheck.xml");
            }
            catch (Exception exception)
            {
                Log(string.Format("Error updating Configuration : {0}", exception.Message));
            }
        }

        private void DisableConfig(CheckSite site)
        {
            XmlDocument xmlDocument = new XmlDocument();
            try
            {
                xmlDocument.Load(@"IPCheck.xml");
                XmlNode root = xmlDocument.SelectSingleNode("Settings");
                XmlNode sites = root.SelectSingleNode("SiteSettings");
                foreach (XmlNode nsite in sites)
                {
                    if (string.Compare(site.HostName, nsite.Attributes.GetNamedItem("Host").Value, StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        nsite.Attributes.GetNamedItem("Disabled").Value = "1";
                    }
                }
                xmlDocument.Save(@"IPCheck.xml");
            }
            catch (Exception exception)
            {
                Log("Error updating Configuration : " + exception.Message);
            }
        }

        private bool UpdateOK(string updateString, string user, string password)
        {
            bool result = false;
            try
            {
                ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => true;
                using (WebClient webClient = new WebClient { Credentials = new NetworkCredential(user, password) })
                {
                    using (StreamReader reader = new StreamReader(webClient.OpenRead(updateString)))
                    {
                        string html = reader.ReadToEnd();
                        if (html.Contains("nochg") || html.Contains("good"))
                        {
                            result = true;
                            //Just a pause of a secound to let the update finish
                            //Was getting error 403 forbidden messages which I think may
                            //have something to do with updating multiple sites too quickly
                            Thread.Sleep(1000);
                        }
                        else
                            Log(html);
                    }
                }
            }
            catch (Exception exception)
            {
                Log("Failed to send update : " + exception.Message);
            }
            return result;

        }

        private bool CheckIpNotExcluded(IPAddress ipAddress)
        {
            try
            {
                bool result = true;
                //Don't include any ipv6 addresses at this stage.
                //so check it falls into the ipv4 regex
                Regex regex = new Regex(@"(\d{1,3}\.){3}\d{1,3}");
                if (!regex.IsMatch(ipAddress.ToString()))
                    return false;
                foreach (IPAddress ip in _excludedIPAddresses)
                {
                    if (ip.Equals(ipAddress))
                    {
                        return false;
                    }
                }
                return result;
            }
            catch (Exception exception)
            {
                Log("Error checking ip exclusion : " + exception.Message);
                return false;
            }
        }

        public static IPAddress GetMyIp()
        {
            try
            {
                Regex regex = new Regex(@"(\d{1,3}\.){3}\d{1,3}");
                using (WebClient webClient = new WebClient())
                {
                    using (StreamReader reader = new StreamReader(webClient.OpenRead(_getIPSiteOne)))
                    {
                        string html = reader.ReadToEnd();
                        return IPAddress.Parse(regex.Matches(html)[0].Groups[0].Value);
                    }
                }
            }
            catch (Exception exception)
            {
                try
                {
                    Log("Error getting web page ip from " + _getIPSiteOne + ": " + exception.Message);
                    Log("Trying site " + _getIPSiteTwo);
                    Regex regex = new Regex(@"(\d{1,3}\.){3}\d{1,3}");
                    using (WebClient webClient = new WebClient())
                    {
                        using (StreamReader reader = new StreamReader(webClient.OpenRead(_getIPSiteTwo)))
                        {
                            string html = reader.ReadToEnd();
                            return IPAddress.Parse(regex.Matches(html)[0].Groups[0].Value);
                        }
                    }
                }
                catch (Exception exception2)
                {
                    Log("Error getting web page ip: " + exception2.Message);
                    return IPAddress.None;
                }
            }
        }

        private static void SendFailedGetIPEmail()
        {
            if (_doEmailNotification)
            {
                MailMessage message = new MailMessage
                {
                    From = new MailAddress(_emailAddress)
                };
                message.To.Add(new MailAddress(_emailAddress));
                if (_failedToGetIP)
                {
                    message.Subject = "IPCheck failed to Get Ip";
                    message.Body = "IPCheck failed to Get ip address at " + DateTime.Now.ToShortDateString() + ' ' + DateTime.Now.ToShortTimeString();
                }
                else
                {
                    message.Subject = "IPCheck resumed checking Ip";
                    message.Body = "IPCheck got ip address at " + DateTime.Now.ToShortDateString() + ' ' + DateTime.Now.ToShortTimeString();
                }
                message.IsBodyHtml = true;
                try
                {
                    SmtpClient smtpClient = new SmtpClient
                    {
                        Host = _smtpAddress,
                        Credentials = new System.Net.NetworkCredential
                         (_smtpUserName, _smtpPassWord),
                        EnableSsl = true,
                        Port = 587
                    };
                    smtpClient.Send(message);
                }
                catch (Exception exception)
                {
                    Log("Error sending email : " + exception.Message);
                    Log(exception.Message);
                }
            }
        }

        private static string FormatDateTime()
        {
            //The good old standard datetime format
            return DateTime.Now.ToString("dd/MM/yy HH:mm:ss");
        }

        private static void Log(string message)
        {
            if (_doLog)
            {
                try
                {
                    FileStream fileStream = new FileStream(@"IPCheck.txt", FileMode.OpenOrCreate, FileAccess.Write);
                    using (StreamWriter writer = new StreamWriter(fileStream))
                    {
                        fileStream.Position = fileStream.Length;
                        writer.WriteLine(string.Format("{0} {1}", FormatDateTime(), message));
                        writer.Flush();
                    }
                    fileStream.Dispose();
                }
                catch (Exception exception)
                {
                    EventLog.WriteEntry("Error in IPCheck Service logging", 
                        exception.ToString(), 
                        EventLogEntryType.Error);
                }
            }
        }

        /// <summary>

        /// OnStop(): Put your stop code here

        /// - Stop threads, set final data, etc.

        /// </summary>

        protected override void OnStop()
        {
            base.OnStop();
        }

        /// <summary>

        /// OnPause: Put your pause code here

        /// - Pause working threads, etc.

        /// </summary>

        protected override void OnPause()
        {
            base.OnPause();
        }

        /// <summary>

        /// OnContinue(): Put your continue code here

        /// - Un-pause working threads, etc.

        /// </summary>

        protected override void OnContinue()
        {
            base.OnContinue();
        }

        /// <summary>

        /// OnShutdown(): Called when the System is shutting down

        /// - Put code here when you need special handling

        ///   of code that deals with a system shutdown, such

        ///   as saving special data before shutdown.

        /// </summary>

        protected override void OnShutdown()
        {
            base.OnShutdown();
        }

        /// <summary>

        /// OnCustomCommand(): If you need to send a command to your

        ///   service without the need for Remoting or Sockets, use

        ///   this method to do custom methods.

        /// </summary>

        /// <param name="command">Arbitrary Integer between 128 & 256</param>

        protected override void OnCustomCommand(int command)
        {
            //  A custom command can be sent to a service by using this method:

            //#  int command = 128; //Some Arbitrary number between 128 & 256

            //#  ServiceController sc = new ServiceController("NameOfService");

            //#  sc.ExecuteCommand(command);


            base.OnCustomCommand(command);
        }

        /// <summary>

        /// OnPowerEvent(): Useful for detecting power status changes,

        ///   such as going into Suspend mode or Low Battery for laptops.

        /// </summary>

        /// <param name="powerStatus">The Power Broadcast Status

        /// (BatteryLow, Suspend, etc.)</param>

        protected override bool OnPowerEvent(PowerBroadcastStatus powerStatus)
        {
            return base.OnPowerEvent(powerStatus);
        }

        /// <summary>

        /// OnSessionChange(): To handle a change event

        ///   from a Terminal Server session.

        ///   Useful if you need to determine

        ///   when a user logs in remotely or logs off,

        ///   or when someone logs into the console.

        /// </summary>

        /// <param name="changeDescription">The Session Change

        /// Event that occurred.</param>

        protected override void OnSessionChange(
                  SessionChangeDescription changeDescription)
        {
            base.OnSessionChange(changeDescription);
        }
    }
}