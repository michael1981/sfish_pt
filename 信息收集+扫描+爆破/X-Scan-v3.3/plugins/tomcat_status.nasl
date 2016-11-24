#
# This script was written by Vincent Renardias <vincent@strongholdnet.com>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, OSVDB ref, output formatting, family change (9/3/09)

include("compat.inc");

if(description)
{
 script_id(11218);
 script_version ("$Revision: 1.6 $");
 # script_cve_id("CVE-MAP-NOMATCH");
 script_xref(name:"OSVDB", value:"561");

 script_name(english:"Apache httpd / Tomcat '/server-status' Information Disclosure");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote web server has an information disclosure vulnerability."
 );
 script_set_attribute(
   attribute:"description",
   value:
"Requesting the URI '/server-status' gives information about the
currently running instance of the remote web server (most likely
Apache httpd or Tomcat).  It also allows anybody to reset the current
statistics.  A remote attacker could use this information to mount
further attacks."
 );
 script_set_attribute(
   attribute:"solution",
   value:
"Disable this feature if it is not being used.  Otherwise, restrict
access to it."
 );
 script_set_attribute(
   attribute:"cvss_vector",
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N"
 );
 script_end_attributes();

 script_summary(english:"Makes a request like http://www.example.com/server-status");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2009 StrongHoldNet");
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/apache");
 
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);


if(get_port_state(port))
{
  buffer = http_get(item:"/status", port:port);
  data = http_keepalive_send_recv(port:port, data:buffer);
  if( ("Status information for" >< data) && ("<a href='jkstatus?scoreboard.reset'>reset</a>" >< data) )
   security_warning(port);
}

