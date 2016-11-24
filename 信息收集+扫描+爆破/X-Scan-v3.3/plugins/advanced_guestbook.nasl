#
# This script was written by Josh Zlatin-Amishav
#
# This script is released under the GNU GPLv2
#


include("compat.inc");

if(description)
{
 script_id(18217);
 script_cve_id("CVE-2005-1548");
 script_bugtraq_id(13548);
 script_xref(name:"OSVDB", value:"16572");
 script_version("$Revision: 1.13 $");

 script_name(english:"Advanced Guestbook index.php entry Parameter SQL Injection");

 script_summary(english:"Checks for a SQL injection attack in Advanced Guestbook");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application written in PHP which is
affected by a SQL injection vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Advanced Guestbook - a guestbook written in PHP.

The remote version of this software contains an input validation flaw leading
to a SQL injection vulnerability. An attacker may exploit this flaw to execute
arbitrary commands against the remote database." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-05/0100.html" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();


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
if ( ! port ) exit(0);

function check(url)
{
 local_var req, res;

 req = http_get(item:url +"/index.php?entry='", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if (  "Query Error" >< res && '1064 You have an error in your SQL syntax.' >< res  )
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
