#
# This script was written by Josh Zlatin-Amishav <josh at tkos dot co dot il>
#
# This script is released under the GNU GPLv2
#
# Changes by Tenable:
# - Revised plugin title (1/02/2009)
# - Added additional CVE and OSVDB refs (1/02/2009)


include("compat.inc");

if(description)
{
 script_id(18362);
 script_version ("$Revision: 1.7 $");

 script_cve_id("CVE-2005-1684", "CVE-2005-1685");
 script_bugtraq_id(13692, 13693);
 script_xref(name:"OSVDB", value:"20684");
 script_xref(name:"OSVDB", value:"20685");

 script_name(english:"Episodex Guestbook Multiple Vulnerabilities (Auth Bypass, XSS)");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP application that is affected by
several issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the Episodex Guestbook, a guestbook written
in ASP. 

The version of Episodex installed on the remote host does not validate
input to various fields in the 'default.asp' script before using it to
generate dynamic HTML. 

In addition, an unauthenticated remote attacker can edit settings by
accessing the application's 'admin.asp' script directly." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-05/0249.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();


 summary["english"] = "Checks for unathenticated access to admin.asp";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_family(english:"CGI abuses");
 script_copyright(english:"Copyright (C) 2005-2009 Josh Zlatin-Amishav");

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_asp(port:port))exit(0);

function check(url)
{
 local_var req, res;
 global_var port;

 req = http_get(item:url +"/admin.asp", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if ( 'Save Configuration' >< res && 'powered by Sven Moderow\'s GuestBook' >< res )
 {
        security_hole(port);
        exit(0);
 }
}

foreach dir ( cgi_dirs() )
  check(url:dir);


