#
# This script was written by Thomas reinke <reinke@e-softinc.com>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, formatted output, changed family (8/18/09)


include("compat.inc");

if(description)
{
 	script_id(10883);
	script_version("$Revision: 1.18 $");
	script_cve_id("CVE-2002-0083");
 	script_bugtraq_id(4241);
	script_xref(name:"OSVDB", value:"730");

 	script_name(english:"OpenSSH < 3.1 Channel Code Off by One Remote Privilege Escalation");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote host." );
 script_set_attribute(attribute:"description", value:
"You are running a version of OpenSSH which is older than 3.1.

Versions prior than 3.1 are vulnerable to an off by one error
that allows local users to gain root access, and it may be
possible for remote users to similarly compromise the daemon
for remote access.

In addition, a vulnerable SSH client may be compromised by
connecting to a malicious SSH daemon that exploits this
vulnerability in the client code, thus compromising the
client system." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH 3.1 or apply the patch for
prior versions. (See: http://www.openssh.org)" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	
script_end_attributes();

 
 	script_summary(english:"Checks for the remote OpenSSH version");
 	script_category(ACT_GATHER_INFO);
 	script_copyright(english:"This script is Copyright (c) 2002-2009 Thomas Reinke");
	script_family(english:"Gain a shell remotely");
	script_dependencie("ssh_detect.nasl");
 	script_require_ports("Services/ssh", 22);
 
 	exit(0);
}


#
# The script code starts here
#

include("backport.inc"); 

port = get_kb_item("Services/ssh");
if(!port) port = 22;


banner = get_kb_item("SSH/banner/" + port );
if ( ! banner ) exit(0);
banner = tolower(get_backport_banner(banner:banner));

if(ereg(pattern:"ssh-.*-openssh[-_](2\..*|3\.0).*" , string:banner))
		security_hole(port);
