#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10648);
 script_bugtraq_id(2548);
 script_version ("$Revision: 1.30 $");
 script_cve_id("CVE-2001-0247");
 script_xref(name:"OSVDB", value:"537");
 script_name(english:"BSD Based FTP Server Multiple glob Function Remote Overflow");
 script_summary(english:"Checks for a buffer overflow in the FTP service");
	     
 script_set_attribute(attribute:"synopsis", value:
"The remote ftp server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"It was possible to make the remote FTP server crash by creating a huge
directory structure and then attempting to list list it using
wildcards. This is usually known as the 'ftp glob overflow' attack. It
may be possible to exploit this to execute arbitrary code.");

 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/freebsd/2001-04/0466.html" );
 script_set_attribute(attribute:"see_also", value:"ftp://patches.sgi.com/support/free/security/advisories/20010802-01-P" );
 script_set_attribute(attribute:"see_also", value:"http://www.openbsd.org/errata28.html#glob_limit" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of your FTP software." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
		 	 
script_end_attributes();

		    
 
 script_category(ACT_MIXED_ATTACK); # mixed
 script_family(english:"FTP");
 
 
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
		  
 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_writeable_directories.nasl");
 script_require_keys("ftp/login", "ftp/writeable_dir");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here : 
#

include("ftp_func.inc");
include("global_settings.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port))exit(0);



if ( report_paranoia == 0 ) exit(0);



# First, we need access
login = get_kb_item("ftp/login");
password = get_kb_item("ftp/password");



# Then, we need a writeable directory
wri = get_kb_item("ftp/writeable_dir");



safe_checks = 0;
if(!login || !password || !wri || safe_checks())safe_checks = 1;


if(safe_checks)
{
 banner = get_ftp_banner(port: port);
 if(banner)
 {
  vuln = 0;
  # FreeBSD
  if(egrep(pattern:"FTP server .version 6\.[0-9][0-9]",
  	  string:banner))vuln = 1;

  # NetBSD	  
  if(egrep(pattern:"NetBSD-ftpd ((19[0-9][0-9].*)|(2000)|(20010(([0-2])|3([0-1]|2[0-8]))))",
  	string:banner)) vuln = 1;
 
 
  # OpenBSD 
  
  # IRIX
  
  # MIT kerberos
  
  
  if(vuln)
  {
  
  security_hole(port:port);
  }
 }
 
 exit(0);
}




# Connect to the FTP server
soc = open_sock_tcp(port);
if(soc)
{
 if(login && wri)
 {
 if(ftp_authenticate(socket:soc, user:login, pass:password))
 {
  # We are in
 
  c = string("CWD ", wri, "\r\n");
  send(socket:soc, data:c);
  b = ftp_recv_line(socket:soc);
  if(!egrep(pattern:"^250.*", string:b))exit(0);
  cwd = string("CWD ", crap(255), "\r\n");
  mkd = string("MKD ", crap(255), "\r\n");
  
  #
  # Repeat the same operation 20 times. After the 20th, we
  # assume that the server is immune (or has a bigger than
  # 5Kb buffer, which is unlikely
  # 
  
  num_dirs = 0;
  
  for(i=0;i<5;i=i+1)
  {
  send(socket:soc, data:mkd);
  b = ftp_recv_line(socket:soc);
 
  if(!egrep(pattern:"^257 .*", string:b) && !("ile exists" >< b)){
  	set_kb_item(name:"ftp/no_mkdir", value:TRUE);
	i = 5;
	}
   else num_dirs = num_dirs + 1;   
  }
  
  
  port2 = ftp_pasv(socket:soc);
  soc2 = open_sock_tcp(port2, transport:get_port_transport(port));
  
  send(socket:soc, data:string("NLST ", wri, "/X*/X*/X*/X*/X*\r\n"));
  b = ftp_recv_line(socket:soc);
  if(!b){
  	security_hole(port);
	set_kb_item(name:"ftp/wu_ftpd_overflow", value:TRUE);
	exit(0);
	}
	
	
	
	
  send(socket:soc,data:cwd);
  b = ftp_recv_line(socket:soc);
  
  ftp_close(socket: soc);
  
  if(!num_dirs)exit(0);
  
  soc = open_sock_tcp(port);
  ftp_authenticate(socket:soc, user:login, pass:password);
  send(socket:soc, data:string("CWD ", wri, "\r\n"));
  b = ftp_recv_line(socket:soc);
  
  for(i=0;i<num_dirs;i=i+1)
  {
   send(socket:soc, data:string("CWD ", crap(255), "\r\n"));
   b = ftp_recv_line(socket:soc); 
  }
  
  for(i=0;i<num_dirs + 1;i=i+1)
  {
   send(socket:soc, data:string("RMD ", crap(255), "\r\n"));
   b = ftp_recv_line(socket:soc);
   
   send(socket:soc, data:string("CWD ..\r\n"));
   b = ftp_recv_line(socket:soc);
  }
 }
}
}
