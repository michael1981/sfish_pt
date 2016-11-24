#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11677);
 script_bugtraq_id(7674);
 script_cve_id("CVE-2003-0392");
 script_xref(name:"OSVDB", value:"4925");
 script_version ("$Revision: 1.15 $");

 script_name(english:"ST FTP Service Arbitrary File/Directory Access");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary files may be read on the remote hosts." );
 script_set_attribute(attribute:"description", value:
"The remote FTP server is vulnerable to a flaw which allows users
to access files which are outside the FTP server root.

An attacker may break out of his FTP jail by issuing the command :

CWD C:" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/322496" );
 script_set_attribute(attribute:"solution", value:
"Contact your vendor for a patch" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();


 summary["english"] = "Attempts to break out of the FTP root";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
 script_require_keys("ftp/login");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

include("global_settings.inc");
include("ftp_func.inc");


function dir()
{
 local_var ls, p, r, result, soc2;
 global_var port, soc;

 p = ftp_pasv(socket:soc);
 if(!p)exit(0);
 soc2 = open_sock_tcp(p, transport:get_port_transport(port));
 if(!soc2)return(0);
 ls = string("LIST .\r\n");
 send(socket:soc, data:ls);
 r = ftp_recv_line(socket:soc);
 if(egrep(pattern:"^150 ", string:r))
 {
  result = ftp_recv_listing(socket:soc2);
  close(soc2);
  r = ftp_recv_line(socket:soc);
  return(result);
 }
 return(0);
}


#
# The script code starts here
#

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port))exit(0);
soc = open_sock_tcp(port);
if(! soc) exit(0);

 login = get_kb_item("ftp/login");
 pass = get_kb_item("ftp/password");

 if(ftp_authenticate(socket:soc, user:login, pass:pass))
 {
 send(socket:soc, data:string("CWD /\r\n"));
 r = ftp_recv_line(socket:soc);
 listing2 = dir();
 if(!listing2)exit(0);

 send(socket:soc, data:string("CWD /\r\n"));
 r = ftp_recv_line(socket:soc);
 listing1 = dir();
 if(!listing1)exit(0);
 if (listing1 != listing2) exit(0);

 send(socket:soc, data:string("CWD C:\r\n"));
 r = ftp_recv_line(socket:soc);
 listing2 = dir();
 if(!listing2)exit(0);

 close(soc);

 if(listing1 != listing2)
   security_warning(port);
 }
