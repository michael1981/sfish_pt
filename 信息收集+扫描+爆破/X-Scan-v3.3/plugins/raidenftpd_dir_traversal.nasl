#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  Ref: joetesta@hushmail.com 
#
#  This script is released under the GNU GPL v2
#
# Changes by Tenable:
# - Revised plugin title, added CVE/OSVDB refs (2/03/2009)

include("compat.inc");

if(description)
{
 script_id(18224);
 script_bugtraq_id(2655);
 script_cve_id("CVE-2001-0491");
 script_xref(name:"OSVDB", value:"7729");
 script_version ("$Revision: 1.5 $");

 script_name(english:"RaidenFTPD Multiple Command Traversal Arbitrary File Access");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote FTP server has a directory traversal vulnerability."
 );
 script_set_attribute(
   attribute:"description",
   value:
"The remote host is running the RaidenFTPD FTP server.  This version
has a directory traversal vulnerability.  An authenticated attacker
could exploit this to read and write arbitrary files outside of the
intended FTP root."
 );
 script_set_attribute(
   attribute:"solution",
   value:"Upgrade to RaidenFTPD 2.1 build 952 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector",
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N"
 );
 script_end_attributes();
 
 summary["english"] = "Detects RaidenFTPD Directory Traversal";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
  
 script_copyright(english:"This script is Copyright (C) 2005-2009 David Maciejak");
 script_family(english:"FTP");
 script_dependencie("find_service1.nasl", "ftp_anonymous.nasl",
 		    "ftpserver_detect_type_nd_version.nasl");
 script_require_keys("ftp/login");
 script_require_ports("Services/ftp", 21);
 
 exit(0);
}

#
# The script code starts here
#

include("ftp_func.inc");
port = get_kb_item("Services/ftp");
if(!port)port = 21;

login = get_kb_item("ftp/login");
password = get_kb_item("ftp/password");

if ( !login || ! password ) exit(0);


if(get_port_state(port))
{
 banner = get_ftp_banner(port: port);
 if ( ! banner ) exit(0);
 if (!egrep(pattern:".*RaidenFTPD.*", string:banner))exit(0);
 soc = open_sock_tcp(port);
 if(soc)
 {
	ftp_recv_line(socket:soc);
       if(ftp_authenticate(socket:soc, user:login, pass:password))
	      {
   		s = string("GET ....\....\autoexec.bat\r\n");
   		send(socket:soc, data:s);
   		r = ftp_recv_line(socket:soc);
		if ("150 Sending " >< r) security_warning(port);
	      }
       close(soc);
  }
}
exit(0);
