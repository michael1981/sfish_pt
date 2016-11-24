#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(34324);
 script_version ("$Revision: 1.7 $");

 script_name(english: "FTP Supports Clear Text Authentication");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server allows credentials to be transmitted in clear
text." );
 script_set_attribute(attribute:"description", value:
"The remote FTP does not encrypt its data and control connections.  The
user name and password are transmitted in clear text and may be
intercepted by a network sniffer, or a man-in-the-middle attack." );
 script_set_attribute(attribute:"solution", value:
"Switch to SFTP (part of the SSH suite) or FTPS (FTP over SSL/TLS). In
the latter case, configure the server such as data and control
connections must be encrypted." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N" );
script_end_attributes();

 
 script_summary(english: "Check if the FTP server accepts passwords in clear text"); 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 script_family(english: "FTP");
 script_require_ports("Services/ftp", 21);
 script_dependencies("ftpserver_detect_type_nd_version.nasl");
 exit(0);
}

#
include("misc_func.inc");
include("ftp_func.inc");

user = get_kb_item('ftp/login');
if (strlen(user) == 0 || user == 'anonymous' || user == 'ftp')
 user = rand_str(length: 8, charset: 'abcdefghijklmnopqrstuvwxyz');
pass = get_kb_item('ftp/password');
if (strlen(pass) == 0) pass = 'root@example.com';

port = get_kb_item("Services/ftp");
if (!port) port = 21;

if ( get_kb_item('ftp/'+port+'/broken') || 
     get_kb_item('ftp/'+port+'/backdoor')) exit(0);

banner = get_ftp_banner(port: port);
if(strlen(banner) == 0 || banner =~ '^[45][0-9][0-9][ -]') exit(0);

trp = get_port_transport(port);
if (trp > ENCAPS_IP) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(0);

b = ftp_recv_line(socket: soc);
if (b =~ '^2[0-9][0-9][ -]')
{
 u = ftp_send_cmd(socket: soc, cmd: 'USER '+user);
 if (u =~ '^3[0-9][0-9][ -]')
 {
  security_note(port);
  # Make FTPD happy
  b = ftp_send_cmd(socket: soc, cmd: 'PASS '+user);
 }
}
ftp_close(socket: soc);
