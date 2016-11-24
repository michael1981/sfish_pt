#
# This script was written by Josh Zlatin-Amishav <josh at tkos dot co dot il>
#
# This script is released under the GNU GPLv2
#
# Changes by Tenable:
# - Revised plugin title, added CVE/OSVDB refs (1/13/2009)


include("compat.inc");

if(description)
{
 script_id(18289);
 script_cve_id("CVE-2005-1633", "CVE-2005-1634");
 script_bugtraq_id(13650);
 # OSVDB XSS refs
 script_xref(name:"OSVDB", value:"16665");
 script_xref(name:"OSVDB", value:"16666");
 script_xref(name:"OSVDB", value:"16667");
 script_xref(name:"OSVDB", value:"16668");
 script_xref(name:"OSVDB", value:"16669");
 script_xref(name:"OSVDB", value:"16670");
 script_xref(name:"OSVDB", value:"16671");
 script_xref(name:"OSVDB", value:"16672");
 # OSVDB SQLi refs
 script_xref(name:"OSVDB", value:"16673");
 script_xref(name:"OSVDB", value:"16674");
 script_xref(name:"OSVDB", value:"16675");
 script_xref(name:"OSVDB", value:"16676");
 script_xref(name:"OSVDB", value:"16677");
 script_xref(name:"OSVDB", value:"16678");
 script_xref(name:"OSVDB", value:"16679");
 script_xref(name:"OSVDB", value:"16680");
 script_xref(name:"OSVDB", value:"16681");

 script_version ("$Revision: 1.7 $");

 script_name(english:"JGS-Portal for WoltLab Burning Board Multiple Vulnerabilities (SQLi, XSS)");

 script_set_attribute(attribute:"synopsis", value:
"The remote web application is vulnerable to several flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the JGS-Portal, a web portal written in PHP.

The remote version of this software contains an input validation flaw leading
multiple SQL injection and XSS vulnerabilities. An attacker may exploit these 
flaws to execute arbirtrary SQL commands against the remote database and to 
cause arbitrary code execution for third party users." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();


 summary["english"] = "JGS-Portal Multiple XSS and SQL injection Vulnerabilities";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_family(english:"CGI abuses");
 script_copyright(english:"Copyright (C) 2005-2009 Josh Zlatin-Amishav");

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);

function check(url)
{
 local_var req, res;

 req = http_get(item:url + "/jgs_portal_statistik.php?meinaction=themen&month=1&year=1'", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);

 if (("SQL-DATABASE ERROR" >< res ) && ("SELECT starttime FROM bb1_threads WHERE FROM_UNIXTIME" >< res ))
 {
     security_hole(port);
     set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
     exit(0);
 }
}

foreach dir ( make_list (cgi_dirs()) )
{
  check(url:dir);
}
