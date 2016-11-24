#
# This script was written by Alexis de Bernis <alexisb@nessus.org>
# 

# Changes by Tenable:
# - rely on the banner if we could not log in
# - changed the description to include a Solution:
# - revised plugin title, removed unrelated CVE ref (2/04/2009)
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
 script_id(10452);
 script_bugtraq_id(726, 1387, 2240);
 script_xref(name:"IAVA", value:"2000-a-0004");
 script_xref(name:"OSVDB", value:"11805");
 script_version ("$Revision: 1.32 $");
 script_cve_id("CVE-2000-0573");
 
 script_name(english:"WU-FTPD site_exec() Function Remote Format String");
             
 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a FTP server with a remote root vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of WU-FTPD running on the remote server does not properly
sanitize the argument of the SITE EXEC command. It may be possible for
a remote attacker to gain root access." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=96171893218000&w=2" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WU-FTPD version 2.6.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 script_summary(english:"Checks if the remote FTP server sanitizes the SITE EXEC command");
 script_category(ACT_ATTACK);
 script_family(english:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 A. de Bernis");
                  
 script_dependencie("find_service1.nasl", "ftp_anonymous.nasl",
 "ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 script_require_keys("ftp/wuftpd");
 exit(0);
}

#
# The script code starts here : 
#

include("global_settings.inc");
include("ftp_func.inc");

login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");



port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port))exit(0);


# Connect to the FTP server
soc = open_sock_tcp(port);
ftpport = port;
if(soc)
{
 if(login)
 {
 if(ftp_authenticate(socket:soc, user:login, pass:pass))
 {
  # We are in
  c = string("SITE EXEC %p \r\n");
  send(socket:soc, data:c);
  b = recv(socket:soc, length:6);
  if(b == "200-0x") security_hole(ftpport);
  quit = string("QUIT\r\n");
  send(socket:soc, data:quit);
  r = ftp_recv_line(socket:soc);
  close(soc);
  exit(0);
  }
  else {
  	close(soc);
	soc = open_sock_tcp(ftpport);
	if (! soc ) exit(0);
	}
 }
  r = ftp_recv_line(socket:soc);
  close(soc);
  if(egrep(pattern:"220.*FTP server.*[vV]ersion wu-((1\..*)|(2\.[0-5]\..*)|(2\.6\.0)).*",
  	 string:r)){
	 report = "
Nessus is solely basing this finding on the version reported
in the banner, so this may be a false positive.
";
	 security_hole(port:ftpport, extra:report);
	 }
}
