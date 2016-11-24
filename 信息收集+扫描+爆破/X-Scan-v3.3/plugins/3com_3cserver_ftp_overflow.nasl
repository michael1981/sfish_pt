#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(16321);
 script_version ("$Revision: 1.13 $");

 script_cve_id("CVE-2005-0276", "CVE-2005-0277", "CVE-2005-0278", "CVE-2005-0419");
 script_bugtraq_id(12155, 12463);
 script_xref(name:"OSVDB", value:"12809");
 script_xref(name:"OSVDB", value:"12810");
 script_xref(name:"OSVDB", value:"12811");
 script_xref(name:"OSVDB", value:"12812");
 script_xref(name:"OSVDB", value:"12813");
 script_xref(name:"OSVDB", value:"13703");
 
 script_name(english:"3Com 3CServer/3CDaemon FTP Server Multiple Vulnerabilities (OF, FS, PD, DoS)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by multiple issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the 3Com 3CServer or 3CDaemon FTP server. 

According to its banner, the version of the 3CServer / 3CDaemon FTP
server on the remote host is reportedly affected by multiple buffer
overflow and format string vulnerabilities as well as an information
leak issue.  An attacker may be able to exploit these flaws to execute
arbitrary code on the remote host with the privileges of the FTP
server, generally Administrator." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/385969" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/389623" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

 script_end_attributes();
 
 script_summary(english:"Checks for 3Com 3CServer FTP Server");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_require_ports("Services/ftp", 21);
 script_dependencies("find_service1.nasl");
 exit(0);
}


include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if ( ! port ) port = 21;

ftpbanner = get_ftp_banner(port:port);
if ( ftpbanner == NULL ) exit(0);
if ( egrep(pattern:"^220 3Com FTP Server Version 1\.[01]([^0-9]|\.)", string:ftpbanner) ||
     egrep(pattern:"^220 3Com 3CDaemon FTP Server Version [0-2]\.", string:ftpbanner)) 
	security_hole(port);
