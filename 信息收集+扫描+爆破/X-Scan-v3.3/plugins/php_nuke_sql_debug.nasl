#
# This script was written by Georges Dagousset <georges.dagousset@alert4web.com>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# See the Nessus Scripts License for details
#
# Changes by Tenable:
# - Changed family (1/21/2009)


include("compat.inc");

if(description)
{
 script_id(10856);
 script_cve_id("CVE-2002-2032");
 script_bugtraq_id(3906);
 script_version("$Revision: 1.11 $");
 script_name(english:"PHP-Nuke sql_debug Information Disclosure");
 script_set_attribute(attribute:"synopsis", value:
"The remote host is vulnerable to information disclosure." );
 script_set_attribute(attribute:"description", value:
"In PHP-Nuke, the sql_layer.php script contains a debugging feature that
may be used by attackers to disclose sensitive information about all SQL 
queries.
Access to the debugging feature is not restricted to administrators." );
 script_set_attribute(attribute:"solution", value:
"Add '$sql_debug = 0;' in config.php." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 script_summary(english:"Make a request like http://www.example.com/?sql_debug=1");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2002-2009 Alert4Web.com");
 script_dependencie("php_nuke_installed.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
installed = get_kb_item("www/" + port + "/php-nuke");
if ( ! installed ) exit(0);
array = eregmatch(pattern:"(.*) under (.*)", string:installed);
if ( ! array ) exit(0);
dir = array[2];


req = http_get(item:dir + "/?sql_debug=1", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if ( res == NULL ) exit(0);
if("SQL query: " >< res){ security_warning(port:port); exit(0); }
