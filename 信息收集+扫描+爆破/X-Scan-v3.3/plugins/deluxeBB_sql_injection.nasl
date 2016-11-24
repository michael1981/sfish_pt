#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  Ref: abducter
#
#  This script is released under the GNU GPL v2
#
# Changes by Tenable:
# - Revised plugin title (12/30/2008)

include("compat.inc");

if(description)
{
 script_id(19750);
 script_version("$Revision: 1.10 $");

 script_cve_id("CVE-2005-2989");
 script_bugtraq_id(14851);
 script_xref(name:"OSVDB", value:"19404");
 script_xref(name:"OSVDB", value:"19405");
 script_xref(name:"OSVDB", value:"19406");
 script_xref(name:"OSVDB", value:"19407");
 script_xref(name:"OSVDB", value:"19408");
 script_xref(name:"Secunia", value:"16819");
 
 script_name(english:"DeluxeBB Multiple Scripts SQL Injection");
 script_summary(english:"Checks DeluxeBB version");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a PHP application that is affected by
multiple SQL injection flaws.");
 script_set_attribute(attribute:"description", value:
"The remote host is using DeluxeBB, a web application forum written in
PHP. 

The installed version of this software fails to sanitize input to
several parameters and scripts before using it to generate SQL
queries.  Provided PHP's 'magic_quotes_gpc' setting is disabled, an
attacker may be able to leverage these issues to manipulate database
queries.");
 script_set_attribute(attribute:"solution", value:
"Upgrade to DeluxeBB version 1.05 or later.");
 script_set_attribute(attribute:"cvss_vector", value:
"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute:"plugin_publication_date", value:
"2005/09/19");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 David Maciejak");
 script_family(english:"CGI abuses");
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
if ( ! can_host_php(port:port) ) exit(0);

function check(loc)
{
 local_var r, req;
 global_var port;

 req = http_get(item:string(loc, "/topic.php?tid='select"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if(isnull(r))exit(0);
 if (("Error querying the database" >< r) && ("DeluxeBB tried to execute: SELECT" >< r))
 {
   security_hole(port);
   set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
   exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
}
