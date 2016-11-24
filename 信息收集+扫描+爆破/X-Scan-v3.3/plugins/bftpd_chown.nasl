#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10579);
 script_bugtraq_id(2120);
 script_version ("$Revision: 1.29 $");
 script_cve_id("CVE-2001-0065", "CVE-2000-0943");
 script_xref(name:"OSVDB", value:"477");
 script_xref(name:"OSVDB", value:"1620");
 
 script_name(english:"bftpd Multiple Command Remote Overflow");
 script_summary(english:"Checks if the remote bftpd daemon is vulnerable to a buffer overflow");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote FTP server has a remote buffer overflow vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The version of bftpd running on the remote host is vulnerable to a\n",
     "remote buffer overflow attack when issued very long arguments to the\n",
     "SITE CHOWN command.  A remote attacker could exploit this issue to\n",
     "crash the FTP server, or possibly execute arbitrary code."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2000-12/0189.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to bftpd version 1.0.24 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_MIXED_ATTACK); # mixed
 script_family(english:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
                  
 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl", "ftp_writeable_directories.nasl", "ftp_kibuv_worm.nasl");
 script_require_ports("Services/ftp", 21);

 exit(0);
}

include("global_settings.inc");
include("ftp_func.inc");

if (report_paranoia < 2) exit(0);

#
# The script code starts here : 
#

login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");

port = get_kb_item("Services/ftp");
if(!port)port = 21;


# Connect to the FTP server

if (get_kb_item('ftp/'+port+'/broken') || 
    get_kb_item('ftp/'+port+'/backdoor')) exit(0);

if(safe_checks())login = 0;


if(login)
{
 if(!get_port_state(port))exit(0);
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 if(ftp_authenticate(socket:soc, user:login, pass:pass))
 {
  req = string("SITE CHOWN AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA A");
  req = req + string("\r\n");
  send(socket:soc, data:req);
  r = ftp_recv_line(socket:soc);
  send(socket:soc, data:string("HELP\r\n"));
  r = ftp_recv_line(socket:soc, retry: 2);
  if(!r)security_hole(port);
  exit(0);
  }
   else {
    	ftp_close(socket: soc);
	}
}
 
banner = get_ftp_banner(port: port);
if(!banner)exit(0);
  
if(egrep(pattern:"220.*bftpd 1\.0\.(([0-9][^0-9])|(1[0-3]))",
  	 string:banner)){
	 data = string(
	   "\n",
	   "Note that Nessus detected this issue solely based on the server banner\n"
	 );
	 security_hole(port:port, extra:data);
	 }

