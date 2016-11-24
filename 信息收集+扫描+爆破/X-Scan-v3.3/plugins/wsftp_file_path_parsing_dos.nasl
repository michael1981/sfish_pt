#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  Ref : lion 
# This script is released under the GNU GPLv2
#
# Changes by Tenable:
# - Revised plugin title (2/03/2009)


include("compat.inc");

if(description)
{
 script_id(14584);
 script_cve_id("CVE-2004-1643");
 script_bugtraq_id(11065);
 script_xref(name:"OSVDB", value:"9382");
 script_version ("$Revision: 1.20 $");

 script_name(english:"WS_FTP Server Path Parsing Remote DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is prone to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of WS_FTP on the remote host is
vulnerable to a remote denial of service. 

There is an error in the parsing of file paths.  Exploitation of this
flaw may cause a vulnerable system to use a large amount of CPU
resources." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/373420" );
 script_set_attribute(attribute:"see_also", value:"http://www.ipswitch.com/support/ws_ftp-server/releases/wr503.asp" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WS_FTP Server 5.03 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C" );

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

if (egrep(pattern:"WS_FTP Server ([0-4]\.|5\.0\.[0-2][^0-9])", string: banner))
	security_hole(port);
