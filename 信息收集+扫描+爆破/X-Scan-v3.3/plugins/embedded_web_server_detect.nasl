#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(19689);
 script_version("$Revision: 1.41 $");
 
 script_name(english:"Embedded Web Server Detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is embedded." );
 script_set_attribute(attribute:"description", value:
"The remote web server cannot host user-supplied CGIs.
CGI scanning will be disabled on this server." );
 script_set_attribute(attribute:"solution", value: "n/a" );
 script_set_attribute(attribute:"risk_factor", value: "None" );

 script_end_attributes();

 script_summary(english: "This scripts detects wether the remote host is an embedded web server");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 
 script_family(english:"Web Servers");
 script_dependencies("cisco_ids_manager_detect.nasl", "ciscoworks_detect.nasl", "ilo_detect.nasl",
"clearswift_mimesweeper_smtp_detect.nasl", "imss_detect.nasl", "interspect_detect.nasl", "intrushield_console_detect.nasl",
"iwss_detect.nasl", "linuxconf_detect.nasl", "securenet_provider_detect.nasl",
"tmcm_detect.nasl", "websense_detect.nasl", "xedus_detect.nasl", "xerox_document_centre_detect.nasl", "xerox_workcentre_detect.nasl", "compaq_wbem_detect.nasl");

 script_require_ports("Services/www", 80);
 exit(0);
}

#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_kb_item("Services/www");
if ( ! port ) port = 80;
if ( ! get_port_state(port) ) exit(0);

if ( get_kb_item("Services/www/" + port + "/embedded") ) exit(0);

banner = get_http_banner(port:port);
if ( ! banner ) exit(0);
if ( port == 901 ||
     egrep(string: banner,
           pattern:"^(DAAP-)?([Ss]erver|SERVER): *(BOSSERV/|CUPS|MiniServ|AppleShareIP|Embedded HTTPD|Embedded HTTP Server.|IP_SHARER|Ipswitch-IMail|MACOS_Personal_Websharing|NetCache appliance|(ZyXEL-)?RomPager/|cisco-IOS|u-Server|eMule|Allegro-Software-RomPager|RomPager|Desktop On-Call|D-Link|4D_WebStar|IPC@CHIP|Citrix Web PN Server|SonicWALL|Micro-Web|gSOAP|CompaqHTTPServer/|BBC [0-9.]+; .*[cC]oda|ida-HTTPServer|HP-Web-JetAdmin|Xerox_MicroServer|HP-ChaiServer|Squid/Alcatel|HTTP Server$|Virata-EmWeb|RealVNC|gSOAP|dncsatm|Tandberg Television Web server|UPSentry|Service admin/|Gordian Embedded|eHTTP|SMF|Allegro-Software-RomPager|3Com/|SQ-WEBCAM|WatchGuard Firewall|Acabit XML-RPC Server|EWS-NIC|3ware/|RAC_ONE_HTTP|GoAhead|BBC|CCM Desktop Agent|iTunes/|LANDesk Management Agent/|Rapid Logic/|NetPort Software|NetEVI/|micro_httpd| UPnP/1\.[01]|WindWeb/|IP-Phone Solution|DCReport/|ESWeb/|Axigen-Webadmin|Axigen-Webmail|glass/.+-IronPort)") )
  set_kb_item(name: "Services/www/"+port+"/embedded", value: TRUE);
