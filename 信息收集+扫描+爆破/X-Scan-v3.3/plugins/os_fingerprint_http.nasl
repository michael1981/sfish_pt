#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25247);
  script_version("$Revision: 1.41 $");

  name["english"] = "OS Identification : HTTP";
  script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"It is possible to identify the remote operating system based
on the response from the remote HTTP server." );
 script_set_attribute(attribute:"description", value:
"This script attempts to identify the Operating System type and 
version by looking at the data returned by the remote HTTP server" );
 script_set_attribute(attribute:"solution", value:
"n/a" );
 script_set_attribute(attribute:"risk_factor", value:"None" );

script_end_attributes();

 
  summary["english"] = "Determines the remote operating system";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
  family["english"] = "General";
  script_family(english:family["english"]);
  script_dependencies("distro_guess.nasl", "find_service1.nasl");
  exit(0);
}


include("http_func.inc");

#
# The Linux distributions are taken care of via distro_guess.nasl
#
if ( (os = get_kb_item("Host/Linux/Distribution")) )
{
  confidence = 95;
  os -= " - ";
  
  if ( "Ubuntu" >< os )
	os = "Linux Kernel 2.6 on " + os;
  else if ( "Debian 4.0 (etch)" >< os )
	os = "Linux Kernel 2.6 on Debian 4.0 (etch)";
  else if ( "Debian 3.1 (sarge)" >< os )
	os = "Linux Kernel 2.4 on Debian 3.1 (sarge)";
  else if ( "Debian 3.0 (woody)" >< os )
	os = "Linux Kernel 2.2 on Debian 3.0 (woody)";
  else if ( "Debian 2.2 (potato)" >< os )
	os = "Linux Kernel 2.2 on Debian 2.2 (potato)";
  else if ( "Debian 2.1 (slink)" >< os )
	os = "Linux Kernel 2.0 on Debian 2.2 (potato)";
  else if ( "Debian 2.0 (hamm)" >< os )
	os = "Linux Kernel 2.0 on Debian 2.2 (potato)";
  else if ( "Debian 1.3 (bo)" >< os )
	os = "Linux Kernel 2.0 on Debian 1.3 (bo)";
  else if ( "Debian 1.2 (rex)" >< os )
	os = "Linux Kernel 2.0 on Debian 1.2 (rex)";
  else if ( "Debian 1.1 (buzz)" >< os )
	os = "Linux Kernel 2.0 on Debian 1.1 (buzz)";
  else if ( "Fedora Core 8" >< os )
	os = "Linux Kernel 2.6 on Fedora Core 8";
  else if ( "Fedora Core 7" >< os )
	os = "Linux Kernel 2.6 on Fedora Core 7";
  else if ( "Fedora Core 6" >< os )
	os = "Linux Kernel 2.6 on Fedora Core 6";
  else if ( "Fedora Core 5" >< os )
	os = "Linux Kernel 2.6 on Fedora Core 5";
  else if ( "Fedora Core 4" >< os )
	os = "Linux Kernel 2.6 on Fedora Core 4";
  else if ( "Fedora Core 3" >< os )
	os = "Linux Kernel 2.6 on Fedora Core 3";
  else if ( "Fedora Core 2" >< os )
	os = "Linux Kernel 2.6 on Fedora Core 2";
  else if ( "Fedora Core 1" >< os )
	os = "Linux Kernel 2.4 on Fedora Core 1";
  else if ( "SuSE Linux 10.3" >< os )
	os = "Linux Kernel 2.6 on SuSE Linux 10.3";
  else if ( "SuSE Linux 10.2" >< os )
	os = "Linux Kernel 2.6 on SuSE Linux 10.2";
  else if ( "SuSE Linux 10.1" >< os )
	os = "Linux Kernel 2.6 on SuSE Linux 10.1";
  else if ( "SuSE Linux 10.0" >< os )
	os = "Linux Kernel 2.6 on SuSE Linux 10.0";
  else if ( "SuSE Linux 9.3" >< os )
	os = "Linux Kernel 2.6 on SuSE Linux 9.3";
  else if ( "SuSE Linux 9.2" >< os )
	os = "Linux Kernel 2.6 on SuSE Linux 9.2";
  else if ( "SuSE Linux 9.1" >< os )
	os = "Linux Kernel 2.6 on SuSE Linux 9.1";
  else if ( "SuSE Linux 9.0" >< os )
	os = "Linux Kernel 2.4 on SuSE Linux 9.0";
  else if ( "SuSE Linux 8.2" >< os )
	os = "Linux Kernel 2.4 on SuSE Linux 8.2";
  else if ( "SuSE Linux 8.0" >< os )
	os = "Linux Kernel 2.4 on SuSE Linux 8.0";
  else if ( "SuSE Linux 7.3" >< os )
	os = "Linux Kernel 2.4 on SuSE Linux 7.3";
  else if ( "SuSE Linux 7.2" >< os )
	os = "Linux Kernel 2.4 on SuSE Linux 7.2";
  else if ( "SuSE Linux 7.1" >< os )
	os = "Linux Kernel 2.2 on SuSE Linux 7.1";
  else if ( "SuSE Linux 6.4" >< os )
	os = "Linux Kernel 2.2 on SuSE Linux 6.4 or 7.0";
  else if ( "SuSE Linux 6.1" >< os )
	os = "Linux Kernel 2.2 on SuSE Linux 6.1";
  else if ( "Red Hat Enterprise Linux 5" >< os )
	os = "Linux Kernel 2.6 on Red Hat Enterprise Linux 5";
  else if ( "Red Hat Enterprise Linux 4" >< os )
	os = "Linux Kernel 2.6 on Red Hat Enterprise Linux 4";
  else if ( "Red Hat Enterprise Linux 3" >< os )
	os = "Linux Kernel 2.4 on Red Hat Enterprise Linux 3";
  else if ( "Red Hat Enterprise Linux 2.1" >< os )
	os = "Linux Kernel 2.4 on Red Hat Enterprise Linux 2.1";
  else if ( "CentOS 5" >< os )
	os = "Linux Kernel 2.6 on CentOS 5";
  else if ( "CentOS 4" >< os )
	os = "Linux Kernel 2.6 on CentOS 4";
  else if ( "CentOS 3" >< os )
	os = "Linux Kernel 2.4 on CentOS 3";
  else if ( "CentOS 2.1" >< os )
	os = "Linux Kernel 2.4 on CentOS 2.1";
  else if ( os =~ "Red Hat Linux ([89]|7\.1)"  )
	os = "Linux Kernel 2.4 on " + os;
  else if ( os =~ "Red Hat Linux (7\.0|6\.)" )
	os = "Linux Kernel 2.2 on " + os;
  else if ( os =~ "Red Hat Linux 5" )
	os = "Linux Kernel 2.0 on " + os;
  else if ( "Mandriva Linux 2007" >< os )
	os = "Linux Kernel 2.6 on " + os;
  else if ( "Mandriva Linux 2006" >< os )
	os = "Linux Kernel 2.6 on " + os;
  else if ( "Mandriva Linux 2005" >< os )
	os = "Linux Kernel 2.6 on " + os;
  else if ( "Mandrake Linux 10.1" >< os )
	os = "Linux Kernel 2.6 on " + os;
  else if ( "Mandrake Linux 10.0" >< os )
	os = "Linux Kernel 2.6 on " + os;
  else if ( "Mandrake Linux 9" >< os )
	os = "Linux Kernel 2.4 on " + os;
  else if ( "Mandrake Linux 8" >< os )
	os = "Linux Kernel 2.4 on " + os;
  else if ( "Mandrake Linux 7" >< os )
	os = "Linux Kernel 2.2 on " + os;
  else confidence -= 20;
  
  set_kb_item(name:"Host/OS/HTTP", value:os);
  set_kb_item(name:"Host/OS/HTTP/Confidence", value:confidence);
  set_kb_item(name:"Host/OS/HTTP/Type", value:"general-purpose");
  exit(0);
}

ports = get_kb_list("Services/www");
if ( isnull(ports) ) exit(0);

ports = make_list(ports);
foreach port ( ports )
{
 if ( ! get_port_state(port) ) exit(0);

 banner = get_http_banner(port:port);
 if ( ! banner ) exit(0);

 svr = egrep(pattern:"^Server", string:banner);
 if ( ! svr ) 
   svr = egrep(pattern:"^[^:]*Server: ", string:banner);
 if ( ! svr ) continue;
 svr = chomp(svr);
 replace_kb_item(name:"Host/OS/HTTP/Fingerprint", value:svr);


 if ( "Microsoft-IIS" >< banner )
 {
  if ( "Microsoft-IIS/3.0" >< banner ) os = "Microsoft Windows NT 4.0";
  else if ( "Microsoft-IIS/4.0" >< banner ) os = "Microsoft Windows NT 4.0";
  else if ( "Microsoft-IIS/5.0" >< banner ) os = "Microsoft Windows 2000 Server";
  else if ( "Microsoft-IIS/6.0" >< banner ) os = "Microsoft Windows Server 2003";
  else if ( "Microsoft-IIS/7.0" >< banner ) os = "Microsoft Windows Server 2008";

  if ( os )
  {
   set_kb_item(name:"Host/OS/HTTP", value:os);
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:75);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"general-purpose");
   exit(0);
  }
 }
 else if ( egrep(pattern:"^Server: (IBM_HTTP_Server.*)?Apache.*Win32",string:banner) )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"Microsoft Windows");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:5);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"general-purpose");
   exit(0);
 }
 else if ( egrep(pattern:"^Server: cisco-IOS",string:banner) )
 {
   if ( egrep(pattern:"^Server: cisco-IOS/[0-9.]+", string:banner) ) 
   {
     version = ereg_replace(string:chomp(egrep(pattern:"^Server: cisco-IOS/[0-9]+\.[0-9]+ ", string:banner)), pattern:"^Server: cisco-IOS/([0-9.]+).*", replace:"\1");
     if ( version =~ "^[0-9.]+" )
	{
    	 set_kb_item(name:"Host/OS/HTTP", value:"CISCO IOS " + version);
   	 set_kb_item(name:"Host/OS/HTTP/Confidence", value:85);
   	 set_kb_item(name:"Host/OS/HTTP/Type", value:"router");
	 exit(0);
	}
   }
   set_kb_item(name:"Host/OS/HTTP", value:"CISCO IOS");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:68);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"router");
   exit(0);
 }
 else if ( egrep(pattern:"^Server: 3Com/v",string:banner) )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"3Com SuperStack Switch");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:10);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"switch");
   exit(0);
 }
 else if ( egrep(pattern:"^Server: NetApp/", string:banner) )
 {
    os = egrep(pattern:"^Server: NetApp/", string:banner);
    os = "NetApp Release " + ereg_replace(pattern:".*NetApp/([0-9.]+).*", string:os, replace:"\1");
    set_kb_item(name:"Host/OS/HTTP", value:os);
    set_kb_item(name:"Host/OS/HTTP/Confidence", value:99);
    set_kb_item(name:"Host/OS/HTTP/Type", value:"proxy");
    exit(0);
 }
 else if ( egrep(pattern:"^Server: Bull-SMW/", string:banner) )
 {
    set_kb_item(name:"Host/OS/HTTP", value:"AIX");
    set_kb_item(name:"Host/OS/HTTP/Confidence", value:10);
    set_kb_item(name:"Host/OS/HTTP/Type", value:"general-purpose");
    exit(0);
 }
 else if ( egrep(pattern:"^Server: HPSMH", string:banner) )
 {
    set_kb_item(name:"Host/OS/HTTP", value:"HP/UX");
    set_kb_item(name:"Host/OS/HTTP/Confidence", value:10);
    set_kb_item(name:"Host/OS/HTTP/Type", value:"general-purpose");
    exit(0);
 }
 else if ( egrep(pattern:"^Server: Jetty/.*HP-UX", string:banner) )
 {
  line =  egrep(pattern:"^Server: Jetty/.*HP-UX", string:banner);
  line = ereg_replace(pattern:".*\((HP-UX.*)\).*", string:line, replace:"\1");
  line = str_replace(string:line, find:"HP-UX", replace:"HP/UX");
   set_kb_item(name:"Host/OS/HTTP", value:line);
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:100);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"general-purpose");
   exit(0);
 }
 else if ( "Server: IP-Phone Solution" >< banner &&
	   'WWW-Authenticate: Basic realm="WirelessIP5000A"' >< banner )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"Hitachi WIP5000 IP Phone Terminal");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:100);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"embedded");
   exit(0);
 }
 else if ( "Server: Web Server" >< banner &&
	   egrep(pattern:"Location: https://[^/*]/webvpn.html", string:banner) )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"CISCO VPN Concentrator");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:100);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"embedded");
   exit(0);
 }
 else if ('WWW-Authenticate: Basic realm="Please enter your user name and password on DSL-502T"' >< banner )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"DLink DSL-502T Modem/Router");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:100);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"router");
   exit(0);
 }
 else if ( "Server: Apache/1.3.33 (Darwin)" >< banner )
 {
   set_kb_item(name:"Host/OS/HTTP", value:'Mac OS X 10.3\nMac OS X 10.4');
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:85);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"general-purpose");
   exit(0);
 }
 else if ( "Server: Apache/1.3.41 (Darwin)" >< banner  )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"Mac OS X 10.4");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:90);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"general-purpose");
   exit(0);
 }
 else if ( "Server: Cisco AWARE 2.0" >< banner && 
           egrep(pattern: "^Set-Cookie: +webvpn[a-z]*=", string: banner) )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"CISCO ASA 5500");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value: 90);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"embedded");
   exit(0);
 }
 else if (egrep(pattern: "^Server: Apache/[12].* \(OpenVMS\)", string: banner))
 {
   set_kb_item(name:"Host/OS/HTTP", value:"OpenVMS");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value: 76);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"general-purpose");
   exit(0);
 }
 else if ("Server: NetPort Software" >< banner)
 {
   set_kb_item(name:"Host/OS/HTTP", value:"Polycom Teleconferencing Device");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value: 69);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"embedded");
   exit(0);
 }
 else if ("Server: Viavideo-Web" >< banner)
 {
   set_kb_item(name:"Host/OS/HTTP", value:"Polycom Teleconferencing Device");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value: 69);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"embedded");
   exit(0);
 }
 else if ( "Server: SonicWALL SSL-VPN Web Server" >< banner )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"SonicWALL SSL-VPN Appliance");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value: 90);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"embedded");
   exit(0);
 }
 else if ( "Server: glass/1.0 Python/2.5.1-IronPort" >< banner )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"AsyncOS");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value: 90);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"embedded");
   exit(0);
 }
 else if ( "Server: BarracudaHTTP 1.00" >< banner )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"Barracuda Spam Filter");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value: 90);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"embedded");
   exit(0);
 }
 else if ( "RIPT-Server: iTunesLib/3." >< banner )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"AppleTV/3.0");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value: 95);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"embedded");
   exit(0);
 }

}
