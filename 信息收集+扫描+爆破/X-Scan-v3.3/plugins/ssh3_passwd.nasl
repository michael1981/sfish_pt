#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10708);;
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-2001-0553");
 script_bugtraq_id(3078);
 script_xref(name:"OSVDB", value:"586");
 script_xref(name:"IAVA", value:"2001-t-0018");
 
 script_name(english:"SSH 3.0.0 Locked Account Remote Authentication Bypass");
 
 script_set_attribute(attribute:"synopsis", value:
"An attacker might be able to use the remote SSH server
to log into the remote host without proper credentials" );
 script_set_attribute(attribute:"description", value:
"The remote host is running SSH 3.0.0.  There is a bug in this 
release which allows any user to log into accounts whose 
password entry is two characters long or less.

An attacker might gain root privileges using this flaw." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 3.0.1 of SSH which solves this problem." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	
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

if("openssh" >< banner)exit(0);

if("3.0.0" >< banner)security_warning(port);
