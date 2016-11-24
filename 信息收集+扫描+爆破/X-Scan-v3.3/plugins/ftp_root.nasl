#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10088);
 script_version ("$Revision: 1.24 $");
 script_cve_id("CVE-1999-0527");
 script_xref(name:"OSVDB", value:"76");

 script_name(english:"Anonymous FTP Writeable root Directory");
 script_summary(english:"Attempts to write on the remote root dir");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server allows write access to the root directory." );
 script_set_attribute(attribute:"description", value:
"It is possible to write on the root directory of this remote anonymous
FTP server. This allows an attacker to upload arbitrary files which
could be used in other attacks, or to turn the FTP server into a
software distribution point." );
 script_set_attribute(attribute:"see_also", value:"http://www.cert.org/advisories/CA-1993-10.html" );
 script_set_attribute(attribute:"solution", value:
"Restrict write access to the root directory." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencie("find_service1.nasl", "ftp_anonymous.nasl");
 script_require_keys("ftp/login");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#
include('ftp_func.inc');
port = get_kb_item("Services/ftp");
if(!port)port = 21;

if(get_port_state(port))
{
login = get_kb_item("ftp/login");
password = get_kb_item("ftp/password");


if(login)
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 if(ftp_authenticate(socket:soc, user:login,pass:password))
 {
  data = string("CWD /\r\n");
  send(socket:soc, data:data);
  a = recv_line(socket:soc, length:1024);
  pasv = ftp_pasv(socket:soc); 
  data = string("STOR nessus_test\r\n");
  send(socket:soc, data:data);
  r = recv_line(socket:soc, length:3);
  if((r == "425")||(r == "150"))
  {
   data = string("DELE nessus_test\r\n");
   send(socket:soc,data:data);
   security_hole(port);
   wri = get_kb_item("ftp/writeable_dir");
   if(!wri)set_kb_item(name:"ftp/writeable_dir", value:"/");
   set_kb_item(name:"ftp/writeable_root", value:TRUE);
  }
 data = string("QUIT\r\n");
 send(socket:soc, data:data);
 }
close(soc);
}
}
