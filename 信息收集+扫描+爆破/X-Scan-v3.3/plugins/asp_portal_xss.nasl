#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(12057);
 script_version ("$Revision: 1.13 $");
 script_bugtraq_id(9659);
 script_xref(name:"OSVDB", value:"3966");
 
 script_name(english:"ASP Portal User Profile XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI that is vulnerable to a cross-
site scripting issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the ASP Portal CGI suite.

There is a cross-site scripting issue in this suite that may allow an
attacker to steal your users cookies." );
 script_set_attribute(attribute:"solution", value:
"See http://www.aspportal.net/downloadsviewer.asp?theurl=38" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 
 script_summary(english:"Checks for ASP Portal");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc."); 
 script_family(english:"CGI abuses : XSS");
 script_dependencie("find_service1.nasl", "http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# The script code starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);
if(!can_host_php(port:port))exit(0);

foreach d ( cgi_dirs() )
{
 r = http_send_recv3(port: port, method: 'GET', item: strcat(d, "/index.asp?inc=<script>foo</script>"));
 if(isnull(r)) exit(0);
 if(r[0] =~ "^HTTP/[0-9]\.[0-9] +200 " &&
    egrep(pattern:"<script>foo</script>", string: r[1]+r[2])){
	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	exit(0);
 }
}
