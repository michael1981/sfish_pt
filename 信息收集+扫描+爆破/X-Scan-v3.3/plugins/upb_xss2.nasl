#
# This script was written by Josh Zlatin-Amishav <josh at ramat dot cc>
#
# This script is released under the GNU GPLv2

# Changes by Tenable:
# - Revised plugin title (4/9/2009)

include("compat.inc");

if(description)
{
 script_id(19499);
 script_version ("$Revision: 1.7 $");
 script_bugtraq_id(14348, 14350);
 script_xref(name:"OSVDB", value:"18143");
 script_xref(name:"OSVDB", value:"18144");
 script_xref(name:"OSVDB", value:"18145");
 script_xref(name:"OSVDB", value:"18146");
 script_xref(name:"OSVDB", value:"18147");

 script_name(english:"Ultimate PHP Board 1.9.6 GOLD Multiple Scripts XSS (1)");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application on the remote host has multiple cross-site
scripting vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running Ultimate PHP Board (UPB).  This version of
UPB has multiple cross-site scripting vulnerabilities.  A remote
attacker could exploit these issues by tricking a user into
requesting a maliciously crafted URL, resulting in the execution of
arbitrary script code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.retrogod.altervista.org/upbgold196xssurlspoc.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/402461"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.retrogod.altervista.org/upbgold196poc.php.txt"
  );
  script_set_attribute(
    attribute:"solution",
    value:"There is no known solution at this time."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N"
  );
  script_end_attributes();

 script_summary(english:"Checks for XSS in send.php");

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
xss = "<script>alert(" + SCRIPT_NAME + ")</script>";
# nb: the url-encoded version is what we need to pass in.
exss = urlencode(str:xss);

foreach dir ( cgi_dirs() )
{
 req = http_get(
   item:string(
     dir, "/chat/send.php?css=",
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
