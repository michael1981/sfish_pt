#
# (C) Tenable Network Security, Inc.
#
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: this domain no longer exists)
#      Added link to the Bugtraq message archive
#


include("compat.inc");


if(description)
{
 script_id(10568);
 script_xref(name:"OSVDB", value:"467");
 script_version ("$Revision: 1.27 $");
 
 script_name(english:"bftpd NLST Command Output Format String");
 script_summary(english:"Checks if the remote bftpd daemon is vulnerable to a format string attack");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote FTP server has a format string vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote FTP server, which appears to be Bftpd, has a format\n",
     "string vulnerability in the NLST command.  A remote attacker could use\n",
     "this to crash the service, or possibly execute arbitrary code."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://marc.info/?l=bugtraq&m=97614485204378&w=2"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Bftpd 1.0.13 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_MIXED_ATTACK);
 script_family(english:"FTP");

 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
                  
 script_dependencie("find_service1.nasl", "ftp_anonymous.nasl", "ftp_writeable_directories.nasl" );
 script_require_ports("Services/ftp", 21);

 exit(0);
}

#
# The script code starts here : 
#

include("ftp_func.inc");

login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");
dir   = get_kb_item("ftp/writeable_dir");


port = get_kb_item("Services/ftp");
if(!port)port = 21;


if(!get_port_state(port))exit(0);

# Connect to the FTP server
soc = open_sock_tcp(port);

if(soc)
{
 if(login && dir && safe_checks() == 0 )
 {
 if(ftp_authenticate(socket:soc, user:login, pass:pass))
 {
  # We are in
  c = string("CWD ", dir, "\r\n");
  send(socket:soc, data:c);
  b = ftp_recv_line(socket:soc);
  c = string("MKD Nessus_test\r\n");
  send(socket:soc, data:c);
  r = ftp_recv_line(socket:soc);
  if(egrep(pattern:"^(257|451)", string:r))
  {
  c = string("CWD Nessus_test\r\n");
  send(socket:soc, data:c);
  r = ftp_recv_line(socket:soc);
  
  c = string("MKD %p%p%p%p\r\n");
  send(socket:soc, data:c);
  r = ftp_recv_line(socket:soc);
  port2 = ftp_pasv(socket:soc);
  soc2 = open_sock_tcp(port2, transport:get_port_transport(port));
  if ( ! soc2 ) exit(0);
  
  c = string("NLST\r\n");
  send(socket:soc, data:c);
  r = ftp_recv_listing(socket:soc2);
  if(ereg(pattern:".*0x[a-f,A-F,0-9]*0x[a-f,A-F,0-9]*0x[a-f,A-F,0-9].*",
  	  string:r))security_hole(port);
  close(soc2);	  
  ftp_close(socket:soc);
  
  soc = open_sock_tcp(port);
  if(!soc)exit(0);
  ftp_authenticate(socket:soc, user:login, pass:pass);
  send(socket:soc, data:string("CWD ", dir, "/Nessus_test\r\n"));
  b = ftp_recv_line(socket:soc);
  send(socket:soc, data:string("RMD %p%p%p%p\r\n"));
  r = ftp_recv_line(socket:soc);
  send(socket:soc, data:string("CWD ..\r\n"));
  r = ftp_recv_line(socket:soc);
  send(socket:soc, data:string("RMD Nessus_test\r\n"));
  r = ftp_recv_line(socket:soc);
  ftp_close(socket:soc);
  exit(0);
  }
   else {
    	close(soc);
	soc = open_sock_tcp(port);
	if ( ! soc ) exit(0);
	}
 }
  else {
  	close(soc);
	soc = open_sock_tcp(port);
	if ( ! soc ) exit(0);
	}
 }
  r = ftp_recv_line(socket:soc);
  close(soc);
  if(egrep(pattern:"220.*bftpd 1\.0\.(([0-9][^0-9])|(1[0-2]))",
  	 string:r)){
	 report = string(
           "\nNessus only verified this vulnerability exists by looking at\n",
           "banner, so this may be a false positive.\n"
         );
	 security_hole(port:port, extra:report);
	 }
}
