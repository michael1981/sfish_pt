#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11395);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-2000-0746");
 script_bugtraq_id(1594, 1595);
 script_xref(name:"OSVDB", value:"9199");

 script_name(english:"Microsoft IIS shtml.dll XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to a cross-site scripting attack." );
 script_set_attribute(attribute:"description", value:
"The remote web server is running with Front Page extensions.  The
remote version of the FrontPage extensions are vulnerable to a cross-
site scripting issue when the CGI /_vti_bin/shtml.dll is provided with
improper parameters." );
 script_set_attribute(attribute:"solution", value:
"http://www.microsoft.com/technet/security/bulletin/ms00-060.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 script_summary(english:"Checks for the presence of a Frontpage XSS");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("http_version.nasl", "cross_site_scripting.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

banner = get_http_banner(port:port);
if ( banner && "IIS" >!< banner ) exit(0);


w = http_send_recv3(method:"GET", item:"/_vti_bin/shtml.dll/<script>alert(document.domain)</script>", port:port);
if (isnull(w)) exit(1, "The web server did not answer");
res = w[2];

if("<script>alert(document.domain)</script>" >< res)
{
 security_warning(port);
 set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}

