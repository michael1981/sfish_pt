#
# (C) Tenable Network Security, Inc.
#
# This script was written by Xue Yong Zhi <yong@tenablesecurity.com>
#
#


include("compat.inc");

if(description)
{
 script_id(11371);
 script_bugtraq_id(2124);
 script_xref(name:"OSVDB", value:"1693");
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-2001-0053");

 script_name(english:"BSD ftpd Single Byte Buffer Overflow");
 script_summary(english:"Checks if the remote ftpd can be buffer overflown");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote ftp server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote ftp daemon contains a flaw in the 'replydirname()' function
which allows an attacker to write a null byte beyond the boundaries of
the local buffer. An attacker can exploit this to gain root access." );
 script_set_attribute(attribute:"see_also", value:"http://www.openbsd.org/advisories/ftpd_replydirname.txt" );
 script_set_attribute(attribute:"see_also", value:"ftp://ftp.openbsd.org/pub/OpenBSD/patches/2.8/common/005_ftpd.patch" );
 script_set_attribute(attribute:"solution", value:
"Apply the fix from the references above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
 script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_family(english:"FTP");

 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");

 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_writeable_directories.nasl");
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

# First, we need anonymous access

login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");

if(!login)exit(0);

# Then, we need a writeable directory
wri = get_kb_item("ftp/writeable_dir");
if(!wri)exit(0);

nomkdir = get_kb_item("ftp/no_mkdir");
if(nomkdir)exit(0);

function clean_exit()
{
  local_var j, r, soc;
  global_var num_dirs;

  soc = open_sock_tcp(port);
  if ( soc )
  {
  ftp_authenticate(socket:soc, user:login, pass:pass);
  send(socket:soc, data:string("CWD ", wri, "\r\n"));
  r = ftp_recv_line(socket:soc);
  for(j=0;j<num_dirs - 1;j=j+1)
  {
   send(socket:soc, data:string("CWD ", crap(144), "\r\n"));
   r = ftp_recv_line(socket:soc);
  }

  for(j=0;j<num_dirs;j=j+1)
  {
   send(socket:soc, data:string("RMD ", crap(144),  "\r\n"));
   r = ftp_recv_line(socket:soc);
   if(!egrep(pattern:"^250 .*", string:r))exit(0);
   send(socket:soc, data:string("CWD ..\r\n"));
   r = ftp_recv_line(socket:soc);
  }
 }
}


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
  cwd = string("CWD ", crap(144), "\r\n");
  mkd = string("MKD ", crap(144), "\r\n");
  pwd = string("PWD \r\n");

  #
  # Repeat the same operation 20 times. After the 20th, we
  # assume that the server is immune.
  #


  for(i=0;i<20;i=i+1)
  {
  send(socket:soc, data:mkd);
  b = ftp_recv_line(socket:soc);

  # No answer = the server has closed the connection.
  # The server should not crash after a MKD command
  # but who knows ?

  if(!b){
  	#security_hole(port);
	clean_exit();
	}

  if(!egrep(pattern:"^257 .*", string:b))
  {
   i = 20;
  }
  else
  {
  send(socket:soc,data:cwd);
  b = ftp_recv_line(socket:soc);

  #
  # See above. The server is unlikely to crash
  # here

  if(!b)
       {
  	#security_hole(port);
	clean_exit();
       }

   if(!egrep(pattern:"^250 .*", string:b))
   {
    i = 20;
   }
   else num_dirs = num_dirs + 1;
   }
  }

  #
  #If vulnerable, it will crash here
  #
  send(socket:soc,data:pwd);
  b = ftp_recv_line(socket:soc, retry: 3);
  if(!b)
       {
  	security_hole(port);
	clean_exit();
       }

  ftp_close(socket:soc);
 }
}
