#
# (C) Tenable Network Security, Inc.
#

#
# Note: This is about SSH.com's SSH, not OpenSSH !!
#


include("compat.inc");

if(description)
{
 script_id(11169);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2002-1644");
 script_bugtraq_id(6247);
 
 script_name(english:"SSH Secure Shell without PTY setsid() Function Privilege Escalation");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote SSH server is affected by a privilege escalation
vulnerability." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of SSH Secure Shell running on
the remote host is between 2.0.13 and 3.2.1.  There is a bug in such
versions that may allow a non-interactive shell session, such as used
in scripts, to obtain higher privileges due to a flaw in the way
setsid() is used." );
 script_set_attribute(attribute:"see_also", value:"http://www.ssh.com/company/newsroom/article/286/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to SSH Secure Shell 3.1.5 / 3.2.2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C" );
script_end_attributes();

 
 script_summary(english:"Checks for the remote SSH version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
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


if("f-secure" >< banner)exit(0);
if("tru64 unix" >< banner)exit(0);
if("windows" >< banner)exit(0);


if(
  (
    ereg(pattern:"^ssh-[0-9]\.[0-9]+-2\..*$", string:banner) &&
    !ereg(pattern:"^ssh-[0-9]\.[0-9]+-2\.0\.([0-9]|0[0-9]|1[0-2])[^0-9].*$", string:banner)
  ) ||
  ereg(pattern:"^ssh-[0-9]\.[0-9]+-3\.(0\..*|1\.[0-4]|2\.[0-1])[^0-9].*$", string:banner)
) security_hole(port);
