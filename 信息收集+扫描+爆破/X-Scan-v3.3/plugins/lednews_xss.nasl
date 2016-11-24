#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11741);
 script_cve_id("CVE-2003-0495");
 script_version ("$Revision: 1.17 $");
 script_bugtraq_id(7920);
 script_xref(name:"OSVDB", value:"2154");

 script_name(english:"LedNews News Post XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a CGI application that is affected by
a cross site scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote web server is running LedNews, a set of scripts designed to
help maintain a news-based website.

There is a flaw in some versions of LedNews which may allow an attacker
to include rogue HTML code in the news, which may in turn be used to
steal the cookies of people visiting this site, or to annoy them
by showing pop-up error messages and such." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/vulnwatch/2003-q2/0105.html" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );


script_end_attributes();

 
 script_summary(english:"Checks for the presence of LedNews");
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) exit(0);
port = get_http_port(default:80);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

function check(loc)
{
 local_var	r;
 r = http_send_recv3(method: "GET", item: strcat(loc, "/"), port:port);
 if (isnull(r)) exit(0);
 if ("<!-- Powered By LedNews: http://www.ledscripts.com -->" >< r[2])
 {
 	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	exit(0);
 }
}

foreach dir (cgi_dirs()) check(loc:dir);
