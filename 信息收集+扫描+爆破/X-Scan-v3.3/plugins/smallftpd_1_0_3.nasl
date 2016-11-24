#
# This script was written by Audun Larsen <larsen@xqus.com>
#
# Changes by Tenable:
# - Revised plugin title, changed family (2/03/2009)
# - Updated to use compat.inc, added CVSS score (11/20/2009)




include("compat.inc");

if(description)
{
 script_id(12072);
 script_cve_id("CVE-2004-0299");
 script_bugtraq_id(9684);
 script_xref(name:"OSVDB", value:"4001");
 script_version("$Revision: 1.10 $");

 script_name(english:"smallftpd 1.0.3 Crafted Traversal Sequence Remote DoS");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by denial
of service vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running smallftpd 1.0.3

It has been reported that SmallFTPD is prone to a remote denial of service 
vulnerability. This issue is due to the application failing to properly 
validate user input." );
 script_set_attribute(attribute:"solution", value:
"Use a different FTP server." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 
 summary["english"] = "Checks for version of smallftpd";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Audun Larsen");
 script_family(english:"FTP");
 script_dependencie("ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc) 
 {
  data = ftp_recv_line(socket:soc);
  if(data)
  {
   if(egrep(pattern:"^220.*smallftpd (0\..*|1\.0\.[0-3][^0-9])", string:data) )
   {
    security_warning(port);
   }
  }
 }
}
