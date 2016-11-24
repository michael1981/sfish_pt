#
# (C) Tenable Network Security, Inc.
#

# Ref:
# From: Damien Miller <djm@cvs.openbsd.org>
# To: openssh-unix-announce@mindrot.org
# Subject: Multiple PAM vulnerabilities in portable OpenSSH
# also covers CVE-2001-1380


include("compat.inc");

if(description)
{
 script_id(11848);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-2003-0786", "CVE-2003-0787");
 script_bugtraq_id(8677);
 script_xref(name:"OSVDB", value:"6071");
 script_xref(name:"OSVDB", value:"6072");
 script_xref(name:"IAVA", value:"2003-t-0020");
 
 script_name(english:"OpenSSH < 3.7.1p2 Multiple Remote Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application which may allow an 
attacker to login potentially as root without password." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host appears to be
running OpenSSH 3.7p1 or 3.7.1p1. These versions are 
vulnerable to a flaw in the way they handle PAM 
authentication when PrivilegeSeparation is disabled.

Successful exploitation of this issue may allow an 
attacker to gain a shell on the remote host using a
null password." );
 script_set_attribute(attribute:"see_also", value:"http://www.kb.cert.org/vuls/id/602204" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH 3.7.1p2 or disable PAM support in sshd_config" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Checks for the remote SSH version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 script_dependencie("ssh_detect.nasl", "os_fingerprint.nasl");
 script_require_ports("Services/ssh", 22);
 exit(0);
}

#
# The script code starts here
#


include("backport.inc"); 
include("global_settings.inc");

port = get_kb_item("Services/ssh");
if(!port)port = 22;

if ( report_paranoia < 2 ) exit(0);

# Windows not affected
os = get_kb_item("Host/OS");
if ( os )
{
 if ( "Linux" >!< os &&
      "SCO" >!< os ) exit(0);
}



banner = get_kb_item("SSH/banner/" + port );
if ( ! banner ) exit(0);

banner = tolower(get_backport_banner(banner:banner));
if(ereg(pattern:".*openssh[-_]3\.7(\.1)?p1", string:banner))
	security_hole(port);	
