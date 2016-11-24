#
# This script was written by Josh Zlatin-Amishav <josh at tkos dot co dot il>
#
# This script is released under the GNU GPLv2
#
# Fixed by Tenable:
#  - added CVE xref.
#  - added BID 13825,
#  - added OSVDB xrefs.
#  - added link to original advisory.


include("compat.inc");

if(description)
{
 script_id(18410);
 script_version ("$Revision: 1.9 $");

 script_cve_id("CVE-2005-1865", "CVE-2005-1866");
 script_bugtraq_id(13825, 13826);
 script_xref(name:"OSVDB", value:"16971");
 script_xref(name:"OSVDB", value:"16972");
 script_xref(name:"OSVDB", value:"16973");
 script_xref(name:"OSVDB", value:"16974");
 script_xref(name:"OSVDB", value:"16975");

 script_name(english:"Calendarix Multiple Vulnerabilities (SQLi, XSS)");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a PHP application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Calendarix, a PHP-based calendar system. 

The remote version of this software is prone to a remote file include
vulnerability as well as multiple cross-site scripting, and SQL
injection vulnerabilities.  Successful exploitation could result in
execution of arbitrary PHP code on the remote site, a compromise of
the application, disclosure or modification of data, or may permit an
attacker to exploit vulnerabilities in the underlying database
implementation." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-05/0356.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.calendarix.com/download_advanced.php" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 1.6.20051111 which fixes this issue." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 summary["english"] = "Checks for multiple vulnerabilities in Calendarix";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
  
 script_copyright(english:"Copyright (C) 2005-2009 Josh Zlatin-Amishav");
 
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);


if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);

function check(url)
{
 local_var r, req;
 global_var port;

 req = http_get(item:string(url, "/cal_week.php?op=week&catview=999'"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if ( r == NULL ) exit(0);
 if ( 'mysql_num_rows(): supplied argument is not a valid MySQL result' >< r )
 {
  security_hole(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check(url:dir);
}
