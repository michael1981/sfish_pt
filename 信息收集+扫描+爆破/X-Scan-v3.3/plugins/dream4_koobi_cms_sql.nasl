#
# This script was written by Josh Zlatin-Amishav <josh at tkos dot co dot il>
#
# This script is released under the GNU GPLv2
#
# Changes by Tenable:
# - Revised plugin title (12/30/2008)

include("compat.inc");

if(description)
{
 script_id(18254);
 script_version ("$Revision: 1.9 $");

 script_cve_id("CVE-2005-1373");
 script_bugtraq_id(13412, 13413);
 script_xref(name:"OSVDB", value:"15997");

 script_name(english:"Dream4 Koobi CMS index.php area Parameter SQL Injection");
 script_summary(english:"Checks for an SQL injection in the Koobi CMS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to a
SQL injection attack.");
 script_set_attribute(attribute:"description", value:
"The remote host is running the Dream4 Koobi CMS, a CMS written in PHP. 

The remote version of this software contains an input validation flaw
leading to a SQL injection vulnerability.  An attacker may exploit
this flaw to execute arbirtrary SQL commands against the remote
database.");
 script_set_attribute(attribute:"see_also", value:
"http://archives.neohapsis.com/archives/bugtraq/2005-04/0461.html");
 script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
 script_set_attribute(attribute:"cvss_vector", value:
"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute:"plugin_publication_date", value:
"2005/06/16");
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

function check(url)
{
 local_var req, res;
 global_var port;

 req = http_get(item:url +"/index.php?p='nessus", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( isnull(res) ) exit(0);
 if ( 'KOOBI-ERROR' >< res && egrep(pattern:"SQL.*MySQL.* 'nessus", string:res) )
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


