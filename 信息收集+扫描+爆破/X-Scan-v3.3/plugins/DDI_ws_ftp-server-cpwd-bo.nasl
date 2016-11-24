#
# Copyright by Digital Defense, Inc. 
# Author: Forrest Rae <forrest.rae@digitaldefense.net>
#
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID and CVE
#
# See the Nessus Scripts License for details
#
# Reference: www.atstake.com/research/advisories/2002/a080802-1.txt
# 

include("compat.inc");

if(description)
{
	script_id(11098);
	script_version ("$Revision: 1.14 $");

	script_cve_id("CVE-2002-0826");
	script_bugtraq_id(5427);
	script_xref(name:"OSVDB", value:"860");

	script_name(english:"WS_FTP Server SITE CPWD Command Remote Overflow");
	script_summary(english:"Checks FTP server banner for vulnerable version of WS_FTP Server");

	script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be run on the remote FTP server." );
	script_set_attribute(attribute:"description", value:
"This host is running a version of WS_FTP FTP server prior to 3.1.2. 
Versions earlier than 3.1.2 contain an unchecked buffer in routines
that handle the 'CPWD' command arguments.  The 'CPWD' command allows
remote users to change their password.  By issuing a malformed
argument to the CPWD command, a user could overflow a buffer and
execute arbitrary code on this host.  Note that a local user account
is required." );
	script_set_attribute(attribute:"solution", value:
"The vendor has released a patch that fixes this issue.  Please
install the latest patch available from the vendor's website at
http://www.ipswitch.com/support/." );
	script_set_attribute(attribute:"cvss_vector", value:
"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_set_attribute(attribute:"plugin_publication_date", value:
"2002/08/21");
	script_end_attributes();

	script_category(ACT_GATHER_INFO); 
	script_family(english:"FTP");
	script_copyright(english:"This script is Copyright (C) 2002-2009 Digital Defense, Inc.");
	script_dependencie("ftpserver_detect_type_nd_version.nasl");
	script_require_ports("Services/ftp", 21);
	exit(0);
}

#
# The script code starts here : 
#
include("global_settings.inc");
include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;

banner = get_ftp_banner(port: port);

if(banner)
{
	if(egrep(pattern:".*WS_FTP Server (((1|2)\..*)|(3\.((0(\..*){0,1})|(1\.1))))", string:banner))
	    		security_hole(port:port);		
}
