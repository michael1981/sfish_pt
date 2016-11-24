#
# written by K-Otik.com <ReYn0@k-otik.com>
#
# osCommerce Cross Site Scripting Bugs
#
# Ref (added by rd) :
#  Message-ID: <009e01c2eef9$069683b0$0900a8c0@compcaw8>
#  From: Daniel Alcántara de la Hoz <seguridad@iproyectos.com>
#  To: <bugtraq@securityfocus.com>
#  Subject: [IPS] osCommerce multiple XSS vulnerabilities
#

# Changes by Tenable:
# - Revised plugin title (5/21/09)


include("compat.inc");

if (description)
{
 script_id(11437);
 script_bugtraq_id(7151, 7153, 7155, 7156, 7158);
 script_version ("$Revision: 1.19 $");
 script_xref(name:"OSVDB", value:"7372");
 script_xref(name:"OSVDB", value:"7374");
 script_xref(name:"OSVDB", value:"7375");
 script_xref(name:"OSVDB", value:"7376");

 script_name(english:"osCommerce 2.2ms1 Multiple Script XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to a cross site scripting flaw." );
 script_set_attribute(attribute:"description", value:
"osCommerce is a widely installed open source shopping e-commerce solution.
An attacker may use it to perform a cross site scripting attack on
this host." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to a newer version." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 script_summary(english:"Determine if osCommerce is vulnerable to xss attack");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"This script is Copyright (C) 2003-2009 k-otik.com");
 script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);
if(!can_host_php(port:port)) exit(0);

dir = make_list(cgi_dirs());



foreach d (dir)
{
 url = string(d, "/default.php?error_message=<script>window.alert(document.cookie);</script>");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
 if( buf == NULL ) exit(0);

 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] +200 .*", string:buf) &&
    "<script>window.alert(document.cookie);</script>" >< buf)
   {
    security_warning(port:port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
   }
}
