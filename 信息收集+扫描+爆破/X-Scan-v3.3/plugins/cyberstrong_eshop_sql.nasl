#
# This script was written by Josh Zlatin-Amishav <josh at tkos dot co dot il>
#
# This script is released under the GNU GPLv2
#
# Fixed by Tenable:
#   - added See also.
#   - Revised plugin title (12/23/2008)


include("compat.inc");

if(description)
{
 script_id(19391);
 script_version ("$Revision: 1.8 $");

 script_cve_id("CVE-2003-0509");
 script_bugtraq_id(14101, 14103, 14112);
 script_xref(name:"OSVDB", value:"10098");
 script_xref(name:"OSVDB", value:"10099");
 script_xref(name:"OSVDB", value:"10100");

 script_name(english:"Cyberstrong eShop Multiple Script ProductCode Parameter SQL Injection");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP script that is affected by
multiple SQL injection flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Cyberstrong eShop, a shopping cart written
in ASP. 

The remote version of this software contains several input validation
flaws leading to SQL injection vulnerabilities.  An attacker may
exploit these flaws to affect database queries, possibly resulting in
disclosure of sensitive information (for example, the admin's user and
password) and attacks against the underlying database." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2003-07/0006.html" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();


 summary["english"] = "Checks for an SQL injection in Cyberstrong eShop v4.2";

 script_summary(english:summary["english"]);

 script_category(ACT_ATTACK);

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
if(!can_host_asp(port:port)) exit(0);

function check(url)
{
 local_var req, res;
 global_var port;

 req = http_get(item:url +"/20Review.asp?ProductCode='", port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if ( res == NULL ) exit(0);
 if ( 'Microsoft OLE DB Provider for ODBC Drivers' >< res && 'ORDER BY TypeID' >< res )
 {
        security_hole(port);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
        exit(0);
 }
}

foreach dir ( cgi_dirs() )
{
  check(url:dir);
}
