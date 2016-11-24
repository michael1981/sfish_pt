#
# (C) Tenable Network Security, Inc. 
#


include("compat.inc");

if(description)
{
 script_id(10009);
 script_bugtraq_id(679);
 script_version ("$Revision: 1.39 $");
 script_cve_id("CVE-1999-0789");
 script_xref(name:"OSVDB", value:"9");
 script_name(english:"AIX FTPd libc Library Remote Buffer Overflow");
 script_summary(english:"Checks for a buffer overflow in the remote FTPd");	     

 script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a remote buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"It was possible to crash the remote FTP server by issuing the
command :

	CEL aaaa[...]aaaa

This problem is known as the 'AIX FTPd' overflow and may allow the
remote user to easily gain access to the root (super-user) account on
the remote system." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/1999-q3/1089.html" );
 script_set_attribute(attribute:"solution", value:
"If you are using AIX FTPd, then read IBM's advisory number
ERS-SVA-E01-1999:004.1, or contact your vendor for a patch." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

		    
 script_category(ACT_MIXED_ATTACK); # mixed
 script_family(english:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
		  
 script_dependencie("find_service1.nasl", "ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 script_exclude_keys("ftp/msftpd","ftp/vxftpd");
 exit(0);
}

#
# The script code starts here : 
#

include("ftp_func.inc");
include("global_settings.inc");

if (report_paranoia < 2) exit(0);

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port))exit(0);

banner = get_ftp_banner(port: port);
if ( ! banner ) exit(0);

if ( ! egrep(pattern:".*FTP server .Version 4\.", string:banner) ) exit(0);

if(safe_checks())
{
 
 if(egrep(pattern:".*FTP server .Version 4\.3.*",
   	 string:banner)){
  	 security_hole(port:port, extra:
"Nessus reports this vulnerability using only information 
that was gathered. Use caution when testing without safe checks 
enabled." );
	 } 
 exit(0);
}

if(get_kb_item("ftp/vxworks"))exit(0); # seperate test for vxworks

soc = open_sock_tcp(port);
if(soc)
{
  buf = ftp_recv_line(socket:soc);
  if(!buf){
 	close(soc);
	exit(0);
	}

  buf = string("CEL a\r\n");
  send(socket:soc, data:buf);
  r = ftp_recv_line(socket:soc);
  if(!r)exit(0);
  buf = string("CEL ", crap(2048), "\r\n");
  send(socket:soc, data:buf);
  b = ftp_recv_line(socket:soc);
  if(!b)security_hole();
  ftp_close(socket: soc);
}

