#
# This script was written by Matt Moore <matt@westpoint.ltd.uk>
#
#   - Added Synopsis, Reference, CVSS Vector
#   - Modified Description

# Changes by Tenable:
# - Standardized title (4/2/2009)
# - Added Synopsis, Referece, CVSS Vector/Modified Description (4/8/2009)


include("compat.inc");

if(description)
{
 script_id(10938);
 script_bugtraq_id(4335);
 script_version("$Revision: 1.20 $");
 script_cve_id("CVE-2002-0061");
 script_xref(name:"OSVDB", value:"769");
 script_summary(english:"Tests for presence of Apache Command execution via .bat vulnerability");

 script_name(english:"Apache on Windows < 1.3.24 / 2.0.34 DOS Batch File Arbitrary Command Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to a remote command execution attack." );
 script_set_attribute(attribute:"description", value:
"The Apache for Win32 before 1.3.24 and 2.0.x before 2.0.34-beta is
shipped with a default script, '/cgi-bin/test-cgi.bat', that allows an
attacker to remotely execute arbitrary commands onthe host subject to
the permissions of the affected application.

An attacker can send a pipe character '|' with commands appended as
parametners, which are then executed by Apache." );
 script_set_attribute(attribute:"see_also", value:"http://www.apacheweek.com/issues/02-03-29#apache1324" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Apache web server 1.3.24 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();


 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2002-2009 Matt Moore");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/apache");
 exit(0);
}

# Check makes request for cgi-bin/test-cgi.bat?|echo - which should return
# an HTTP 500 error containing the string 'ECHO is on'
# We just check for 'ECHO' (capitalized), as this should remain the same across
# most international versions of Windows(?)

include("http_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port)){ exit(0); }

if ( get_kb_item("Services/www/" + port + "/embedded") ) exit(0);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "Apache" >!< sig ) exit(0);

soc = http_open_socket(port);
if (!soc) exit(0);

req = http_get(item:"/cgi-bin/test-cgi.bat?|echo", port:port);
send(socket:soc, data:req);
res = http_recv(socket:soc);
http_close_socket(soc);
if ("ECHO" >< res)
{
    security_hole(port:port);
}
