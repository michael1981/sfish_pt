#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  Ref : Marc <marc@EEYE.COM>
# This script is released under the GNU GPLv2
#
# Changes by Tenable:
# - Revised plugin title, added OSVDB ref (2/03/2009)

include("compat.inc");

if(description)
{
 script_id(14586);
 script_bugtraq_id(217);
 script_cve_id("CVE-1999-0362");
 script_xref(name:"OSVDB", value:"937");
 script_version ("$Revision: 1.8 $");

 script_name(english:"WS_FTP Server CWD Command Remote DoS");
  script_set_attribute(
    attribute:"synopsis",
    value:"The remote FTP server has a denial of service vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the version of WS_FTP running on the remote
host has a denial of service vulnerability.  Sending a 'CWD' command
followed by a long argument causes the service to crash."
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to the latest version of WS_FTP."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P"
  );
  script_end_attributes(); 
 
 summary["english"] = "Check WS_FTP server version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 
 script_family(english:"FTP");
 script_dependencie("find_service1.nasl", "ftp_anonymous.nasl",
 		    "ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 
 exit(0);
}

#

include ("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port) port = 21;
if (! get_port_state(port)) exit(0);

banner = get_ftp_banner(port:port);

if (egrep(pattern:"WS_FTP Server 1\.0\.[0-2][^0-9]", string: banner))
	security_warning(port);
