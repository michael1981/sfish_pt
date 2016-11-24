#
# This script was written by Thomas Reinke <reinke@securityspace.com>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, formatted output, enhanced solution, changed plugin family (8/18/09)


include("compat.inc");

if(description)
{
 script_id(10954);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-2002-0575");
 script_bugtraq_id(4560);
 script_xref(name:"OSVDB", value:"781");
 script_xref(name:"IAVA", value:"2002-t-0011");
 
 script_name(english:"OpenSSH Kerberos TGT/AFS Token Passing Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote host." );
 script_set_attribute(attribute:"description", value:
"You are running a version of OpenSSH older than OpenSSH 3.2.1

A buffer overflow exists in the daemon if AFS is enabled on
your system, or if the options KerberosTgtPassing or
AFSTokenPassing are enabled.  Even in this scenario, the
vulnerability may be avoided by enabling UsePrivilegeSeparation.

Versions prior to 2.9.9 are vulnerable to a remote root
exploit. Versions prior to 3.2.1 are vulnerable to a local
root exploit." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 3.2.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Checks for the remote SSH version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2009 Thomas Reinke");
 script_family(english:"Gain a shell remotely");
 if (  ! defined_func("bn_random") ) 
	script_dependencie("ssh_detect.nasl");
 else
	script_dependencie("ssh_detect.nasl", "redhat-RHSA-2002-131.nasl");
 script_require_ports("Services/ssh", 22);
 exit(0);
}

#
# The script code starts here
#


include("backport.inc"); 

if ( get_kb_item("CVE-2002-0640") ) exit(0);

port = get_kb_item("Services/ssh");
if(!port)port = 22;


banner = get_kb_item("SSH/banner/" + port );
if(!banner)exit(0);


banner = tolower(get_backport_banner(banner:banner));

if(ereg(pattern:".*openssh[-_](2\..*|3\.([01].*|2\.0)).*", 
	string:banner)) security_hole(port);
