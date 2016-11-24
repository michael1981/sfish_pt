#
# (C) Tenable Network Security
#

include("compat.inc");

if(description)
{
   script_id(15781);
   script_cve_id("CVE-2004-1540");
   script_bugtraq_id(11723);
   script_xref(name:"OSVDB", value:"12108");
   script_xref(name:"Secunia", value:"13278");
   script_version ("$Revision: 1.11 $");
   
   script_name(english:"ZyXEL Prestige Router Configuration Reset");
   script_summary(english:"Tries to access an unrestricted admin webpage");

   script_set_attribute(
     attribute:"synopsis",
     value:string(
       "The remote host is a router with a web vulnerability that allows\n",
       "a remote attacker to reset its configuration to factory defaults."
     )
   );
   script_set_attribute(
     attribute:"description", 
     value:string(
       "The remote host is a ZyXEL router with a vulnerability in its web\n",
       "interface.  With HTTP Remote Administration enabled, the page\n",
       "'/rpFWUpload.html' does not require authentication. This allows an\n",
       "attacker to reset the router's configuration to its factory state."
     )
   );
   script_set_attribute(
     attribute:"see_also",
     value:"http://archives.neohapsis.com/archives/bugtraq/2004-11/0274.html"
   );
   script_set_attribute(
     attribute:"solution", 
     value:"Contact ZyXEL for a patch."
   );
   script_set_attribute(
     attribute:"cvss_vector", 
     value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N"
   );
   script_end_attributes();

   script_category(ACT_GATHER_INFO);
   script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
   script_family(english:"Misc.");
   script_dependencie("http_version.nasl");
   script_require_ports(80);

   exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if ( "ZyXEL-RomPager" >!< banner ) exit(0);

r = http_send_recv3(method:"GET", item:"/fpFWUpload.html", port:port);
if (isnull(r)) exit(0);
res = r[2];
if ( egrep(pattern:'<INPUT TYPE="BUTTON" NAME="ResetDefault" VALUE=".*" onClick="ConfirmDefault()"></div></td></tr><tr>', string:res ) )
	security_warning(port);
