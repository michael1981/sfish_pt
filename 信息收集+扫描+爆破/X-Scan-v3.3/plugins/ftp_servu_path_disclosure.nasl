#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11392);
 script_cve_id("CVE-2000-0176", "CVE-1999-0838");
 script_bugtraq_id(859, 1016);
 script_xref(name:"OSVDB", value:"11278");
 script_xref(name:"OSVDB", value:"13632");
 script_version ("$Revision: 1.17 $");
 
 script_name(english:"Serv-U < 2.5e Multiple Vulnerabilities (OF, Path Disc)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by multiple issues." );
 script_set_attribute(attribute:"description", value:
"The remote FTP server discloses the full path to its root through a
CWD command for a nonexistent directory. 

In addition, the server may be prone to a buffer overflow that may
allow a remote authenticated attacker to launch a denial of service
attack against the affected software." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/1999-q4/0176.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2000-02/0417.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Serv-U 2.5e or newer" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();

 
 summary["english"] = "FTP path disclosure";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencie("find_service1.nasl", "ftp_anonymous.nasl");
 script_require_keys("ftp/anonymous");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;

if(! get_port_state(port)) exit(0);

login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");

if(! login) login="ftp";
if (! pass) pass="test@nessus.com";

 banner = get_ftp_banner(port:port);
 if ( ! banner || "Serv-U FTP Server" >!< banner ) exit(0);
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 if(ftp_authenticate(socket:soc, user:login,pass:pass))
 {
   send(socket:soc, data:string("CWD ", rand(), rand(), "-", rand(), "\r\n"));
   r = ftp_recv_line(socket:soc);
   if(egrep(pattern:"^550.*/[a-z]:/", string:r, icase:TRUE))security_warning(port);
   ftp_close(socket: soc);
   exit(0);
 }

#
# Could not log in
# 
 r = get_ftp_banner(port: port);
if(egrep(pattern:"^220 Serv-U FTP-Server v2\.(([0-4])|(5[a-d]))", string:r))
 	security_warning(port);
