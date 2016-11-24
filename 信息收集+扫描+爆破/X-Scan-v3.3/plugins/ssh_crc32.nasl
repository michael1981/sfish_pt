#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10607);
 script_version ("$Revision: 1.27 $");
 script_cve_id("CVE-2001-0144");
 script_bugtraq_id(2347);
 script_xref(name:"IAVA", value:"2001-A-0013");
 script_xref(name:"OSVDB", value:"795");
 
 script_name(english:"SSH CRC-32 Compensation Attack Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to execute arbitrary code on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of SSH which is older than version 1.2.32,
or a version of OpenSSH which is older than 2.3.0.

The remote version of this software is vulnerable to a flaw known as a 'CRC-32
compensation attack' which may allow an attacker to gain a root shell on this 
host." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 1.2.32 of SSH which solves this problem,
or to version 2.3.0 of OpenSSH" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	
script_end_attributes();

 
 script_summary(english:"Checks for the remote SSH version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 script_dependencie("ssh_detect.nasl");
 script_require_ports("Services/ssh", 22);
 exit(0);
}

#
# The script code starts here
#
include("backport.inc");

port = get_kb_item("Services/ssh");
if(!port)port = 22;


banner = get_kb_item("SSH/banner/" + port );
if ( ! banner ) exit(0);

banner = tolower(get_backport_banner(banner:banner));

if("openssh" >< banner)
{
 if(ereg(pattern:"ssh-.*-openssh(-|_)((1\..*)|2\.[0-2]([^0-9]|$))",
	 string:banner))security_hole(port);
}
else
{
if(ereg(pattern:"ssh-.*-1\.2\.(2[4-9]|3[01])([^0-9]|$)", string:banner))
	security_hole(port);
}
