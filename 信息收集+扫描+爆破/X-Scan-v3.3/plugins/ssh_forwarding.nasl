#
# This script was written by Xue Yong Zhi<xueyong@udel.edu>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, changed family (8/6/09)
# - Updated to use compat.inc (11/20/2009)


include("compat.inc");

if(description)
{
 script_id(11343);
 script_version ("$Revision: 1.10 $");

 script_cve_id("CVE-2000-1169");
 script_bugtraq_id(1949);
 script_xref(name:"OSVDB", value:"2114");
 script_xref(name:"OSVDB", value:"6248");
 
 script_name(english:"OpenSSH Client Unauthorized X11 Remote Forwarding");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote SSH client does not disable X11 forwarding." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of the OpenSSH client older than
2.3.0. 
 
Such versions do not properly disable X11 or agent forwarding, which
could allow a malicious SSH server to gain access to the X11 display
and sniff X11 events, or gain access to the ssh-agent." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH 2.3.0 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
 script_summary(english:"Checks for the remote SSH version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Xue Yong Zhi");
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

	
# Looking for OpenSSH product version number < 2.3
if(ereg(pattern:".*openssh[_-](1|2\.[0-2])\..*",string:banner))security_hole(port);
