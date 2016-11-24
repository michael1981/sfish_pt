#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10771);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-2001-1380");
 script_bugtraq_id(3369);
 script_xref(name:"OSVDB", value:"642");
 
 script_name(english:"OpenSSH 2.5.x - 2.9.x Multiple Key Type ACL Bypass");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that may allow bypassing
IP based access control restrictions." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host appears to be 
running OpenSSH version between 2.5.x and 2.9.x. Such 
versions reportedly fail to correctly enforce IP based 
access control restrictions.

Depending on the order of the user keys in 
~/.ssh/authorized_keys2, sshd might fail to apply the 
source IP based access control restriction to the 
correct key. This problem allows users to circumvent
the system policy and login from disallowed source 
IP address." );
 script_set_attribute(attribute:"see_also", value:"http://www.kb.cert.org/vuls/id/905795" );

 script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH 2.9.9" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	
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

if(ereg(pattern:".*openssh[-_]2\.(([5-8]\..*)|(9\.[0-8])).*",
	string:banner))
{
 security_warning(port);
}
