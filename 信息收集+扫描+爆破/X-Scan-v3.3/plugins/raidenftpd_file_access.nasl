#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  Ref: Lachlan. H
#
#  This script is released under the GNU GPL v2
#
# Changes by Tenable:
# - Revised plugin title (2/03/2009)

include("compat.inc");

if(description)
{
 script_id(18225);
 script_cve_id("CVE-2005-1480");
 script_bugtraq_id(13292);
 script_xref(name:"OSVDB", value:"15713");
 script_version ("$Revision: 1.7 $");

 script_name(english:"RaidenFTPD urlget Command Traversal Arbitrary File Access");

 script_set_attribute(
  attribute:"synopsis",
  value:"The remote FTP server has a directory traversal vulnerability."
 );
 script_set_attribute(
  attribute:"description",
  value:
"The remote host is running the RaidenFTPD FTP server.  This version
has a directory traversal vulnerability that could allow an attacker
to read arbitrary files outside of the intended FTP root."
 );
 script_set_attribute(
  attribute:"see_also",
  value:"http://archives.neohapsis.com/archives/bugtraq/2005-05/0024.html"
 );
 script_set_attribute(
  attribute:"solution",
  value:"Upgrade to RaidenFTPD 2.4 build 2241 or later."
 );
 script_set_attribute(
  attribute:"cvss_vector",
  value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
 );
 script_end_attributes();
 
 summary["english"] = "Detects RaidenFTPD Unauthorized File Access";
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

if ( ! login || ! password ) exit(0);

banner = get_ftp_banner(port: port);
if ( ! banner ) exit(0);
if (!egrep(pattern:".*RaidenFTPD.*", string:banner))exit(0);


if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
 	     ftp_recv_line(socket:soc);
	     if(ftp_authenticate(socket:soc, user:login, pass:password))
	      {
   		s = string("quote site urlget file:/..\\boot.ini\r\n");
   		send(socket:soc, data:s);
   		r = ftp_recv_line(socket:soc);
		if ("220 site urlget " >< r) security_warning(port);

	      }
	close(soc);
  }
}
