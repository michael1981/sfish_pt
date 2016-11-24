#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#      Should also cover BugtraqID: 4560, BugtraqID: 4241/(CVE-2002-0083)
# 
# If the plugin is successful, it will issue a security_hole(). Should
# it attempt to determine if the remote host is a kerberos client and
# issue a security_warning() if it's not ?
#


include("compat.inc");

if(description)
{
 script_id(10802);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-2001-1507");
 script_bugtraq_id(3560);
 script_xref(name:"OSVDB", value:"20216");
 
 script_name(english:"OpenSSH < 3.0.2 Multiple Flaws");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by 
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host appears to be
running OpenSSH version 3.0.1 or older. Such versions
are reportedly affected by multiple flaws :

  - Provided KerberosV is enabled (disabled by default),
    it may be possible for an attacker to partially
    authenticate.

  - It may be possible to crash the daemon due to a 
    excessive memory clearing bug.

  - A vulnerability exists in an environment where
    UseLogin sshd option is passed." );
 script_set_attribute(attribute:"see_also", value:"http://www.openbsd.org/errata30.html#sshd" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH 3.0.2" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );

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
 if(ereg(pattern:".*openssh[-_]((1\..*)|(2\..*)|(3\.0[^\.]))[^0-9]*", string:banner))
	security_warning(port);
}
