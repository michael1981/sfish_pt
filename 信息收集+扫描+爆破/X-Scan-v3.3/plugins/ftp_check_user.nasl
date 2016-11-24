#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10082);
 script_version ("$Revision: 1.17 $");
 script_name(english:"FTPd CWD Command Account Enumeration");
 script_summary(english:"Checks fot the existance of a user");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is vulnerable by an account enumeration attack." );
 script_set_attribute(attribute:"description", value:
"It is possible to determine the existence of a user on the remote 
system by issuing the command CWD ~<username>.
	
An attacker may use this to determine the existence of known to be 
vulnerable accounts (like guest) or to determine which system you 
are running." );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencie("ftp_anonymous.nasl", "ftpserver_detect_type_nd_version.nasl");
 script_require_keys("ftp/anonymous");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#
include('ftp_func.inc');
port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port))exit(0);
if (get_kb_item('ftp/'+port+'/backdoor')
 || get_kb_item('ftp/'+port+'/broken')) exit(0);

anon = get_kb_item("ftp/anonymous");
if(anon)
{
 soc = open_sock_tcp(port);
 if ( ! soc ) exit(0);
 if(ftp_authenticate(socket:soc, user:"anonymous",pass:"nessus@"))
 {
  data = string("CWD ~root\r\n");
  send(socket:soc, data:data);
  a = recv_line(socket:soc, length:1024);
  if(a)
  {
  if("550 /" >< a)security_warning(port);
  }
  data = string("QUIT\r\n");
  send(socket:soc, data:data);
 }
close(soc);
}
