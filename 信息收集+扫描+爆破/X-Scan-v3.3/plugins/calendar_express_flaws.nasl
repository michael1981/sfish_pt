#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  Ref: aLMaSTeR HacKeR
#
#  This script is released under the GNU GPL v2
#

# Changes by Tenable:
# - changed family (4/28/09)


include("compat.inc");

if(description)
{
 script_id(19749);
 script_version("$Revision: 1.11 $");

 script_cve_id("CVE-2007-3627");
 script_bugtraq_id(14504, 14505);
 script_xref(name:"OSVDB", value:"18638");
 script_xref(name:"OSVDB", value:"38941");
 script_xref(name:"OSVDB", value:"38942");
 script_xref(name:"OSVDB", value:"38943");
 
 script_name(english:"Calendar Express Multiple Vulnerabilities (SQLi, XSS)");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script which is vulnerable to
cross-site scripting and SQL injection attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is using Calendar Express, a PHP web calendar. 

Vulnerability exist in this version which may allow an attacker to
execute arbitrary HTML and script code in the context of the user's
browser, and SQL injection. 

An attacker may exploit these flaws to use the remote host to perform
attacks against third-party users, or to execute arbitrary SQL
statements on the remote SQL database." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of this software." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_summary(english:"Checks Calendar Express XSS and SQL flaws");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 David Maciejak");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:80);

if ( !get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

function check(loc)
{
 local_var r, req;
 req = http_get(item:string(loc, "/search.php?allwords=<br><script>foo</script>&cid=0&title=1&desc=1"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if ( "<script>foo</script>" >< r && egrep(string:r, pattern:"Calendar Express [0-9].+ \[Powered by Phplite\.com\]") )
 {
   	security_hole(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
   exit(0);
 }
}

if (thorough_tests) dirs = list_uniq(make_list("/calendarexpress", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
 check(loc:dir);
}
