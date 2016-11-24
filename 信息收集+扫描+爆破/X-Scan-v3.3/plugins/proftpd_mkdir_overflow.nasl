#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10189);
 script_bugtraq_id(612);
 script_version ("$Revision: 1.38 $");
 script_cve_id("CVE-1999-0911");
 
 script_name(english:"ProFTPD mkdir Buffer Overflow");
	     
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is vulnerable to a buffer overflow attack." );
 script_set_attribute(attribute:"description", value:
"It is possible to crash the remote FTP service by creating a large
number of nested directories with names no longer than 255 chars. 
This issue is known to affect ProFTPD, although other FTP servers may
be affected as well. 

It is likely that a remote attacker can leverage this issue to execute
arbitrary code on the remote host, subject to the privileges under
which the service runs." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/1999-q3/0632.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/1999-q3/0651.html" );
 script_set_attribute(attribute:"solution", value:
"Configure the service so that directories are not writable by
'anonymous' or any untrusted users. 

If running ProFTPD, upgrade to version 1.2.0pre6 or later; otherwise,
contact the vendor to see if an update exists." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();


 script_summary(english:"Checks if the remote ftp can be buffer overflown");
 script_category(ACT_MIXED_ATTACK); # mixed
 script_family(english:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
		  
 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_writeable_directories.nasl", "wu_ftpd_overflow.nasl");
 script_require_keys("ftp/login", "ftp/writeable_dir", "Settings/ParanoidReport");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here : 
#
include("global_settings.inc");
include("ftp_func.inc");

if (report_paranoia < 2) exit(0);

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if (! get_port_state(port)) exit(0);
if (get_kb_item('ftp/'+port+'/broken') || 
    get_kb_item('ftp/'+port+'/backdoor')) exit(0);

if(safe_checks())
{
 banner = get_ftp_banner(port: port);
 if(banner)
 {
   if(egrep(pattern:"^220 ProFTPD 1\.2\.0pre[1-5][^0-9]", string:banner))
   {
     report = string(
       "\n",
       "Note that Nessus has determined the vulnerability exists based solely\n",
       "on the following service banner :\n",
       "\n",
       "  ", banner
     );
     security_hole(port:port, extra:report);
   }
 }
 exit(0);
}


# First, we need anonymous access

login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");

if(!login)exit(0);

# Then, we need a writeable directory
wri = get_kb_item("ftp/writeable_dir");
if(!wri)exit(0);



ovf = get_kb_item("ftp/wu_ftpd_overflow");
if(ovf)exit(0);

nomkdir = get_kb_item("ftp/no_mkdir");
if(nomkdir)exit(0);

# Connect to the FTP server
soc = open_sock_tcp(port);
if(soc)
{
 if(ftp_authenticate(socket:soc, user:login, pass:pass))
 {
  num_dirs = 0;
  # We are in
 
  c = string("CWD ", wri, "\r\n");
  send(socket:soc, data:c);
  b = ftp_recv_line(socket:soc);
  cwd = string("CWD ", crap(254), "\r\n");
  mkd = string("MKD ", crap(254), "\r\n");
  
  #
  # Repeat the same operation 20 times. After the 20th, we
  # assume that the server is immune (or has a bigger than
  # 5Kb buffer, which is unlikely
  # 
  
  
  for(i=0;i<20;i=i+1)
  {
  send(socket:soc, data:mkd);
  b = ftp_recv_line(socket:soc, retry: 3);
  
  # No answer = the server has closed the connection. 
  # The server should not crash after a MKD command
  # but who knows ?
  
  if(!b){
  	security_hole(port);
	exit(0);
	}
	
  if(!egrep(pattern:"^257 .*", string:b))
  {
   i = 20;
  }
  else
  {
  send(socket:soc,data:cwd);
  b = ftp_recv_line(socket:soc, retry: 3);
  
  #
  # See above. The server is likely to crash
  # here
  
  if(!b)
       {
  	security_hole(port);
	exit(0);
       }
       
   if(!egrep(pattern:"^250 .*", string:b))
   {
    i = 20;
   }
   else num_dirs = num_dirs + 1;
   }
  }
  ftp_close(socket:soc);
  
  if(!num_dirs)exit(0);
  
  soc = open_sock_tcp(port);
  if(!soc)exit(0);
  
  ftp_authenticate(socket:soc, user:login, pass:pass);
  send(socket:soc, data:string("CWD ", wri, "\r\n"));
  r = ftp_recv_line(socket:soc);
  for(j=0;j<num_dirs;j=j+1)
  {
   send(socket:soc, data:string("CWD ", crap(254), "\r\n"));
   r = ftp_recv_line(socket:soc);
  }
  
  for(j=0;j<num_dirs + 1;j=j+1)
  {
   send(socket:soc, data:string("RMD ", crap(254),  "\r\n"));
   r = ftp_recv_line(socket:soc);
   if(!egrep(pattern:"^250 .*", string:r))exit(0);
   send(socket:soc, data:string("CWD ..\r\n"));
   r = ftp_recv_line(socket:soc);
  }
 }
}

