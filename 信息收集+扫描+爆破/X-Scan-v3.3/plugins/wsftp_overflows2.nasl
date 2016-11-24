#
# (C) Tenable Network Security
#

include("compat.inc");

if(description)
{
 script_id(15857);
 script_bugtraq_id(11772);
 script_cve_id("CVE-2004-1135");
 script_xref(name:"OSVDB", value:"12509");
 script_version ("$Revision: 1.6 $");

 script_name(english:"WS_FTP Server Multiple Command Remote Overflow DoS");
 script_set_attribute(attribute:"synopsis", value:"The remote FTP server is vulnerable to a buffer overflow vulnerabilty");
 script_set_attribute(attribute:"description", value:"
According to its version number, the remote WS_FTP server is
vulnerable to multiple buffer overflows which may be used by an
attacker to execute arbitrary code on the remote system.");
 script_set_attribute(attribute:"solution", value:"Upgrade to the latest version of this software.");
 script_set_attribute(attribute:"cvss_vector", value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_end_attributes();

 summary["english"] = "Check WS_FTP server version";
  script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 
 script_family(english:"FTP");
 script_dependencie("find_service1.nasl", "ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 
 exit(0);
}

#

include ("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port) port = 21;
if (! get_port_state(port)) exit(0);
banner = get_ftp_banner(port:port);
if ( ! banner ) exit(0);

if (egrep(pattern:"WS_FTP Server ([0-4]\.|5\.0\.[0-3][^0-9])", string: banner))
	security_hole(port);
