#
# Josh Zlatin-Amishav <josh at ramat dot cc>
#
# This script is released under the GNU GPLv2
#

# Changes by Tenable:
# - Revised plugin title (5/20/09)


include("compat.inc");

if(description)
{
 script_id(19945);
 script_version ("$Revision: 1.9 $");
 script_cve_id("CVE-2005-3152");
 script_bugtraq_id(14962);
 script_xref(name:"OSVDB", value:"19860");
 script_xref(name:"OSVDB", value:"19861");

 script_name(english:"CubeCart < 3.0.4 Multiple Script XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains several PHP scripts that are prone to
cross-site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"The remote version of CubeCart contains several cross-site scripting
vulnerabilities to due to its failure to properly sanitize user-
supplied input of certain variables to the 'index.php' and 'cart.php'
scripts." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ff7a638f" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to CubeCart version 3.0.4 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();


 script_summary(english:"Checks for XSS in index.php");
 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"Copyright (C) 2005-2009 Josh Zlatin-Amishav");
 script_dependencies("cross_site_scripting.nasl","cubecart_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");


port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);
if ( get_kb_item("www/"+port+"/generic_xss") ) exit(0);

# Make sure this is really cubecart
install = get_kb_item(string("www/", port, "/cubecart"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 ver = matches[1];
 dir = matches[2];

 # A simple alert.
 xss = "<script>alert('" + SCRIPT_NAME + "');</script>";
 # nb: the url-encoded version is what we need to pass in.
 exss = urlencode(str:xss);

 req = http_get(
   item:string(
     dir, "/index.php?",
     'searchStr=">', exss, 
     "&act=viewCat&Submit=Go"
   ), 
   port:port
 );
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

 if ( xss >< res )
 {
        security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
        exit(0);
 }
}
