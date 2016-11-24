#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(11610);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-2003-1531");
 script_bugtraq_id(7214);
 script_xref(name:"OSVDB", value:"40593");

 script_name(english:"Ceilidh testcgi.exe query Parameter XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has a CGI installed that is affected by a
cross-site scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host has a CGI called 'testcgi.exe' installed
under /cgi-bin which is vulnerable to a cross site scripting
issue." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to a newer version." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english:"Determine if testcgi.exe is vulnerable to xss");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

dir = make_list(cgi_dirs());
		
foreach d (dir)
{
 url = string(d, '/testcgi.exe?<script>x</script>');
 res = http_send_recv3(method:"GET", item:url, port:port);

 if(isnull(res)) exit(0);
 
 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:res[0]) &&
    "<script>x</script>" >< res[2])
   {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
   }
}
