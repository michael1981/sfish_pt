#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  Ref: benji lemien <benjilenoob@hotmail.com>
#
#  This script is released under the GNU GPL v2
#


include("compat.inc");

if(description)
{
 script_id(15785);
 script_cve_id("CVE-2004-2725");
 script_bugtraq_id( 11654 );
 script_xref(name:"OSVDB", value:"11704");
 script_version("$Revision: 1.10 $");
 
 script_name(english:"Aztek Forum Multiple Script XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is vulnerable to a
cross-site scripting issue" );
 script_set_attribute(attribute:"description", value:
"The remote host is using Aztek Forum, a web forum written in PHP. 

A vulnerability exists the remote version of this software - more
specifically in the script 'forum_2.php', that may allow an attacker
to set up a cross-site scripting attack using the remote host." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of this software" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 
 summary["english"] = "Checks XSS in Aztek Forum";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
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

if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port))exit(0);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit ( 0 );

function check_dir(path)
{
 local_var req, res;
 global_var port;

 req = http_get(item:string(path, "/forum_2.php?msg=10&return=<script>foo</script>"), port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if ( res == NULL ) exit(0);

 if ( "forum_2.php?page=<script>foo</script>" >< res )
 {
  security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  exit(0);
 }
}

foreach dir ( cgi_dirs() )
{
 check_dir(path:dir);
}
 
