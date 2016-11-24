#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# 
# Ref: Cyrille Barthelemy <cb-publicbox ifrance com>
#
# This script is released under the GNU GPL v2

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref (5/21/09)


include("compat.inc");

if(description)
{
  script_id(15850);
  script_version("$Revision: 1.11 $");
  script_cve_id("CVE-2004-1202");
  script_bugtraq_id(11765);
  script_xref(name:"OSVDB", value:"12134");
  
  script_name(english:"phpCMS parser.php file Parameter XSS");

 script_set_attribute(attribute:"synopsis", value:
"A remote web application is vulnerable to cross site scripting." );
 script_set_attribute(attribute:"description", value:
"The remote host runs phpCMS, a content management system 
written in PHP.

This version is vulnerable to cross-site scripting due to a lack of 
sanitization of user-supplied data in parser.php script.
Successful exploitation of this issue may allow an attacker to execute 
malicious script code on a vulnerable server." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 1.2.1pl1 or newer" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

  script_summary(english:"Checks phpCMS XSS");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
  script_family(english:"CGI abuses : XSS");
  script_require_ports("Services/www", 80);
  script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

#the code

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

buf = http_get(item:"/parser/parser.php?file=<script>foo</script>", port:port);
r = http_keepalive_send_recv(port:port, data:buf, bodyonly:0);
if( r == NULL )exit(0);

if(
egrep(pattern:"^HTTP/1\.[01] +200 ", string:r) &&
egrep(pattern:"<script>foo</script>", string:r)
)
{
  security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  exit(0);
}
