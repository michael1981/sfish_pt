#
# This script was written by Josh Zlatin-Amishav <josh at ramat dot cc>
#
# This script is released under the GNU GPLv2


include("compat.inc");

if(description)
{
 script_id(19500);
 script_bugtraq_id(14396);
 script_xref(name:"OSVDB", value:"18306");
 script_xref(name:"OSVDB", value:"18307");
 script_xref(name:"OSVDB", value:"18308");
 script_xref(name:"OSVDB", value:"18309");
 script_xref(name:"OSVDB", value:"18310");
 script_xref(name:"OSVDB", value:"18311");
 script_xref(name:"OSVDB", value:"18312");
 script_xref(name:"OSVDB", value:"18313");
 script_version ("$Revision: 1.10 $");

 script_name(english:"BMForum Multiple Script XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is vulnerable to
cross-site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running BMForum, a web forum written in PHP.

The remote version of this software is affected by several cross-site
scripting vulnerabilities.  The issues are due to failures of the
application to properly sanitize user-supplied input." );
 script_set_attribute(attribute:"see_also", value:"http://lostmon.blogspot.com/2005/07/multiple-cross-site-scripting-in.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();


 summary["english"] = "Checks for XSS in topic.php";

 script_summary(english:summary["english"]);

 script_category(ACT_ATTACK);

 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"Copyright (C) 2005-2009 Josh Zlatin-Amishav");

 script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");

# nb: avoid false-posiives caused by not checking for the app itself.
if (report_paranoia < 2) exit(0);

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);
if ( get_kb_item("www/"+port+"/generic_xss") ) exit(0);

# A simple alert.
xss = '"><script>alert(" + SCRIPT_NAME + ")</script>';
# nb: the url-encoded version is what we need to pass in.
exss = urlencode(str:xss);

foreach dir ( cgi_dirs() )
{
 req = http_get(
   item:string(
     dir, "/topic.php?filename=1",
     exss
   ), 
   port:port
 );


 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if (isnull(res)) exit(0);

 if ( xss >< res )
 {
        security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
        exit(0);
 }
}
