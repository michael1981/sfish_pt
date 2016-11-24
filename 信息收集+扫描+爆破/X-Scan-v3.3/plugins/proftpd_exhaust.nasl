#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added link to the Bugtraq message archive
#
# References:
# Date:  Thu, 15 Mar 2001 22:30:24 +0000
# From: "The Flying Hamster" <hamster@VOM.TM>
# Subject: [SECURITY] DoS vulnerability in ProFTPD
# To: BUGTRAQ@SECURITYFOCUS.COM
#
#   Problem commands include:
#   ls */../*/../*/../*/../*/../*/../*/../*/../*/../*/../*/../*/../*
#   ls */.*/*/.*/*/.*/*/.*/*/.*/*/.*/*/.*/*/.*/*/.*/*/.*/*/.*/*/.*/
#   ls .*./*?/.*./*?/.*./*?/.*./*?/.*./*?/.*./*?/.*./*?/.*./*?/.*./*?/
# 
#   Other commands of this style may also cause the same behavior; the exact
#   commands listed here are not necessary to trigger.
# 



include("compat.inc");

if(description)
{
 script_id(10634);
 script_bugtraq_id(6341);
 script_xref(name:"OSVDB", value:"10768");
 script_version ("$Revision: 1.27 $");
 
 script_name(english:"ProFTPD STAT Command Remote DoS");
             
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is prone to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"The remote FTP server seems to consume all available memory on the
remote host when it receives a specially-crafted command." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/303007/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"If using ProFTPD, upgrade to version 1.2.2 and modify the
configuration file to include :

	DenyFilter \*.*/
	
Otherwise, contact your vendor." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C" );
                 
script_end_attributes();

                    
 
 script_summary(english:"Checks if the version of the remote proftpd");
 script_category(ACT_ATTACK);
 script_family(english:"FTP");

 
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
                  
 script_dependencie("find_service1.nasl", "ftp_anonymous.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here : 
#

function test(soc, port, login, pass)
{
  local_var	pasv_port, soc2, req, code, data;
  if(! ftp_authenticate(socket: soc, user: login, pass: pass)) return;
  pasv_port = ftp_pasv(socket: soc);
  soc2 = open_sock_tcp(pasv_port, transport: get_port_transport(port));
  if (! soc2) return;

  req = 'NLST /../*/../*/../\r\n';
  send(socket:soc, data:req);
  code = ftp_recv_line(socket:soc);
  if(strlen(code))
    data = ftp_recv_listing(socket:soc2);
  else
  {
    close(soc2);
    return;
  }
  debug_print(1, 'Received data=', data);
  if("Permission denied" >!< data && "Invalid command" >!< data &&
     egrep(string:data, pattern:"/\.\./[^/]*/\.\./") )
    security_hole(port);
  close(soc2);
  return;
}

include("global_settings.inc");
include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(! get_port_state(port))exit(0);
login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");

banner = get_ftp_banner ( port : port );
proftpd = egrep(pattern:"^220 ProFTPD ((1\.1\..*)|(1\.2\.(0|1)[^0-9]))", string:banner);

if (report_paranoia < 1 && ! proftpd) exit(0);
if (!login || safe_checks())
{
  if (proftpd) security_hole(port, extra: '\nNessus only checked the banner of the FTP server\n');
  exit(0);
}

soc = open_sock_tcp(port);
if (! soc) exit(0);
test(soc: soc, login: login, pass: pass, port: port);
ftp_close(socket: soc);

