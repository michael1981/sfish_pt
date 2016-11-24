#
#  Written by K-Otik.com <ReYn0@k-otik.com>
#
#  DCP-Portal Cross Site Scripting Bugs
#
#  Message-ID: <1642444765.20030319015935@olympos.org>
#  From: Ertan Kurt <mailto:ertank@olympos.org>
#  To: <bugtraq@securityfocus.com>
#  Subject: Some XSS vulns
#
#  Modified by David Maciejak <david dot maciejak at kyxar dot fr>
#  add ref:  Alexander Antipov <antipov@SecurityLab.ru>

# Changes by Tenable:
# - Revised plugin title (4/28/09)

include("compat.inc");

if (description)
{
 script_id(11446);
 script_version ("$Revision: 1.28 $");

 script_cve_id("CVE-2003-1536", "CVE-2004-2511", "CVE-2004-2512");
 script_bugtraq_id(7141, 7144, 11338, 11339, 11340);
 script_xref(name:"OSVDB", value:"7021");
 script_xref(name:"OSVDB", value:"7022");
 script_xref(name:"OSVDB", value:"10585");
 script_xref(name:"OSVDB", value:"10587");
 script_xref(name:"OSVDB", value:"10588");
 script_xref(name:"OSVDB", value:"10589");
 script_xref(name:"OSVDB", value:"10590");
 script_xref(name:"OSVDB", value:"11405");

 script_name(english:"DCP-Portal Multiple Script XSS");
 script_summary(english:"Check for DCP-Portal XSS flaws");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple issues.");
 script_set_attribute(attribute:"description", value:
"The version of DCP-Portal installed on the remote host fails to
sanitize input to the script 'calendar.php' before using it to
generate dynamic HTML, which may let an attacker execute arbitrary
code in the browser of a legitimate user. 

It may also be affected by HTML injection flaws, which may let an
attacker to inject hostile HTML and script code that could permit
cookie-based credentials to be stolen and other attacks, and HTTP
response splitting flaw, which may let an attacker to influence or
misrepresent how web content is served, cached or interpreted. 

DCP-Portal has been reported to be vulnerable to an HTTP response
splitting attack via the PHPSESSID parameter when passed to the
calendar.php script.  However, Nessus has not checked for this issue.");
 script_set_attribute(attribute:"see_also", value:
"http://archives.neohapsis.com/archives/bugtraq/2004-10/0042.html");
 script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
 script_set_attribute(attribute:"cvss_vector", value:
"CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_attribute(attribute:"plugin_publication_date", value:
"2003/03/23");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"This script is Copyright (C) 2003-2009 k-otik.com & Copyright (C) 2004-2009 David Maciejak");
 script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

# nb: avoid false-posiives caused by not checking for the app itself.
if (report_paranoia < 2) exit(0);

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

foreach d (cgi_dirs())
{
 url = string(d, "/calendar.php?year=2004&month=<script>foo</script>&day=01");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( buf == NULL ) exit(0);
 if( "<script>foo</script>" >< buf )
   {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
   }
}
