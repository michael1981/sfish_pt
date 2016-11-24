#
# (C) Tenable Network Security, Inc.
#

#
# UNTESTED!
#


include("compat.inc");


if(description)
{
 script_id(10545);
 script_version ("$Revision: 1.24 $");
 script_cve_id("CVE-2000-0945");
 script_bugtraq_id(1846);
 script_xref(name:"OSVDB", value:"444");

 script_name(english:"Cisco Catalyst Web Interface Remote Command Execution");
 script_summary(english:"Obtains the remote router configuration");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote router has a command execution vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote device appears to be a Cisco Catalyst.  It is\n",
     "possible to execute arbitrary commands on the router by requesting\n",
     "them via HTTP, as in :\n\n",
     "  /exec/show/config/cr\n\n",
     "This command shows the configuration file, which contains passwords.\n",
     "A remote attacker could use this flaw to take control of the router."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2000-10/0380.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.cisco.com/warp/public/cc/pd/si/casi/ca3500xl/index.shtml"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Disable the web configuration interface."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english:"CISCO");
 script_dependencie("find_service1.nasl", "httpver.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if(get_port_state(port))
{
 banner = get_http_banner(port:port);
 if ( "cisco-IOS" >!< banner ) exit(0);

 soc = http_open_socket(port);
 if(soc)
 {
  r = http_send_recv3(method:"GET", item:"/exec/show/config/cr", port:port);

  if(("enable" >< r) &&
     ("interface" >< r) &&
     ("ip address" >< r))security_hole(port);
  }
}
