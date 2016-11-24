#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  Ref: SSR Team
#  This script is released under the GNU GPL v2
#

# Changes by Tenable:
# - Revised plugin title (5/20/09)


include("compat.inc");

if(description)
{
 script_id(15566);
 script_version("$Revision: 1.10 $");
 
 script_cve_id("CVE-2004-1632");
 script_bugtraq_id(11516);
 script_xref(name:"OSVDB", value:"11124");

 script_name(english:"MoniWiki < 1.0.9 wiki.php XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a PHP application that is affected
by a cross-site scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running MoniWiki, a wiki web application 
written in PHP.

The remote version of this software is vulnerable to cross-site 
scripting attacks, through the script 'wiki.php'.

With a specially crafted URL, an attacker can cause arbitrary code 
execution in users' browsers resulting in a loss of integrity." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2004-10/0986.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MoniWiki version 1.0.9 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 script_summary(english:"Test for XSS flaw in MoniWiki");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
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
if(!can_host_php(port:port))exit(0);

foreach d (cgi_dirs())
{
 req = http_get(item:string(d, "/wiki.php/<script>foo</script>"), port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( res == NULL ) exit(0);
 if("<wikiHeader>" >< res && "<script>foo</script>" >< res )
 {
 	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	exit(0);
 }
}
