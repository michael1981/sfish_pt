#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  Ref: Sullo
#  This script is released under the GNU GPL v2
#

# Changes by Tenable:
# - Revised plugin title, removed non-XSS OSVDB ref (5/20/09)


include("compat.inc");

if(description)
{
 script_id(16093);
 script_version("$Revision: 1.7 $");
 script_bugtraq_id(12133);
 script_xref(name:"OSVDB", value:"12606");
 script_xref(name:"OSVDB", value:"12607");
 script_xref(name:"OSVDB", value:"12608");
 script_xref(name:"OSVDB", value:"12609");
 
 script_name(english:"MySQL Eventum Multiple Script XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a PHP application that is affected by
a cross-site scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running MySQL Eventum, a user-friendly 
and flexible issue tracking system written in PHP.

The remote version of this software is vulnerable to cross-site 
scripting attacks, through multiple scripts.

With a specially crafted URL, an attacker can use the remote server to
perform an attack against third party users of the remote service, in
order to steal their credentials." );
 script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=7552" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 script_summary(english:"Test flaws in MySQL Eventum");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"This script is Copyright (C) 2005-2009 David Maciejak");
 script_dependencie("cross_site_scripting.nasl");
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
if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);
if(!can_host_php(port:port))exit(0);


foreach d (cgi_dirs())
{
 req = http_get(item:d + "/index.php?err=3&email=<script>foo</script>", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 if("<title>Login - Eventum</title>" >< res && egrep(pattern:"<script>foo</script>", string:res) )
 {
 	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	exit(0);
 }
}
