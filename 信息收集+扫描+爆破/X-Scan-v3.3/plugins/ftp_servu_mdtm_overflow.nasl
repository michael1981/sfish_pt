#
# (C) Tenable Network Security
# 


include("compat.inc");

if(description)
{
 script_id(12080);
 script_cve_id("CVE-2004-0330");
 script_bugtraq_id(9751);
 script_xref(name:"OSVDB", value:"4073");
 script_xref(name:"Secunia", value:"10989");
 script_version ("$Revision: 1.14 $");
 
 script_name(english:"Serv-U MDTM Command Overflow");
 script_summary(english:"Serv-U Stack Overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Serv-U FTP server.

There is a bug in the way this server handles arguments to the MDTM 
requests which may allow an attacker to trigger a buffer overflow against
this server, which may allow him to disable this server remotely or to
execute arbitrary code on this host." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2004-02/0654.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Serv-U 5.0.0.4 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();
 script_category(ACT_MIXED_ATTACK);
 script_family(english:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
		  
 script_require_ports("Services/ftp", 21);
 script_dependencie("find_service1.nasl", "ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");

 exit(0);
}

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port))exit(0);

banner = get_ftp_banner(port:port);
if ( ! banner ) exit(0);

if("Serv-U FTP Server " >!< banner )exit(0);

login = get_kb_item("ftp/login");
password = get_kb_item("ftp/password");
banner = get_ftp_banner(port:port);
if ( ! banner || "Serv-U FTP Server" >!< banner ) exit(0);
if (!login || safe_checks()) {

 if(egrep(pattern:"Serv-U FTP Server v(([0-3]\..*)|(4\.[0-2]\.))", string:banner))security_hole(port: port, extra:
 "Nessus only check the version number in the server banner.
To really check the vulnerability, disable safe_checks"); 
 exit(0);
}


if(login)
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 if(ftp_authenticate(socket:soc, user:login,pass:password))
 {
 crp = crap(data:"a", length:2000);
 req = string("MDTM ", crp, "\r\n");
 send(socket:soc, data:req);
 r = recv_line(socket:soc, length:4096);
 if(!r)
 {
  security_hole(port);
  exit(0);
 }
 data = string("QUIT\r\n");
 send(socket:soc, data:data);
 }
 close(soc);
}
