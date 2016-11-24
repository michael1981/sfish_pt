#
# (C) Tenable Network Security, Inc.
#

#
# Ref:
#  From: "Ferruh Mavituna" <ferruh@mavituna.com>
#  To: <bugtraq@securityfocus.com>
#  Subject: EzPublish Directory XSS Vulnerability
#  Date: Fri, 16 May 2003 06:22:20 +0300
#


include("compat.inc");

if (description)
{
 script_id(11644);
 script_version ("$Revision: 1.20 $");

 script_cve_id("CVE-2003-0310");
 script_bugtraq_id(7616);
 script_xref(name:"OSVDB", value:"6554");

 script_name(english:"eZ Publish articleview.php XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is running an application that is vulnerable to
a cross site scripting attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is using ezPublish, a content management system.

There is a flaw in the remote ezPublish which lets an attacker
perform a cross site scripting attack.  An attacker may use this
flaw to steal the cookies of your legitimate users." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2003-05/0186.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to ezPublish 3" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N" );

script_end_attributes();

 script_summary(english:"Determine if ezPublish is vulnerable to xss attack");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80, embedded: 0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);
if (get_kb_item("www/no404/"+port)) exit(0);
if(!can_host_php(port:port)) exit(0);

foreach d (cgi_dirs())
{
 url = string(d, '/index.php/article/articleview/<img%20src="javascript:alert(document.cookie)">');
 r = http_send_recv3(method: 'GET', item:url, port:port);
 if (isnull(r)) exit(0);

 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] +200 ", string: r[0]) &&
    'src="javascript:alert(document.cookie)' >< r[2])
   {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
   }
}

