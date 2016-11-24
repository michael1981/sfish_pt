#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  Released under the GNU GPL v2
#  Ref: Mindwarper <mindwarper at hush.com>
#


include("compat.inc");

if (description)
{
 script_id(16315);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2003-1204");
 script_bugtraq_id(6571, 6572);
 script_xref(name:"OSVDB", value:"7495");
 script_xref(name:"OSVDB", value:"7496");
 script_xref(name:"OSVDB", value:"7497");
 script_xref(name:"OSVDB", value:"7498");
 script_xref(name:"OSVDB", value:"7499");
 script_xref(name:"OSVDB", value:"7500");
 script_xref(name:"OSVDB", value:"7501");
 script_xref(name:"OSVDB", value:"7502");
 script_xref(name:"OSVDB", value:"7503");
 script_xref(name:"OSVDB", value:"7504");
 script_xref(name:"OSVDB", value:"7505");
 script_xref(name:"OSVDB", value:"7507"); # Mambo administrator/upload.php Arbitrary Command Execution
 script_xref(name:"OSVDB", value:"7508");

 script_name(english:"Mambo Site Server Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to
multiple attacks." );
 script_set_attribute(attribute:"description", value:
"An attacker may use the installed version of Mambo Site Server to
perform a cross-site scripting attack on this host or execute
arbitrary code through the gallery image uploader under the
administrator directory." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/306206" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Determine if Mambo Site Server is vulnerable to xss attack and remote flaw");
 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2005-2009 David Maciejak");
 script_dependencies("mambo_detect.nasl", "cross_site_scripting.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);
if(!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/mambo_mos"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 dir = matches[2];

 url = string(dir, "/themes/mambosimple.php?detection=detected&sitename=</title><script>foo</script>");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( buf == NULL ) exit(0);
 
 if ( '<a href="?detection=detected&sitename=</title><script>foo</script>' >< buf )
 {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
 }
}
