#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10439);
 script_version ("$Revision: 1.21 $");

 script_cve_id("CVE-2000-0525");
 script_bugtraq_id(1334);
 script_xref(name:"OSVDB", value:"341");

 script_name(english:"OpenSSH < 2.1.1 UseLogin Local Privilege Escalation");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a local 
privilege escalation vulnerability." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host appears to be 
running OpenSSH version older than 2.1.1. Such versions are
reportedly affected by a local privilege esclation 
vulnerability.

If the UseLogin option is enabled, then sshd does not switch
to the uid of the user logging in.  Instead, sshd relies on 
login(1) to do the job.  However, if the user specifies a 
command for remote execution, login(1) cannot be used and 
sshd fails to set the correct user id, so the command is run 
with the same privilege as sshd (usually root privileges)." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH 2.1.1 or make sure that the 
option UseLogin is set to no in sshd_config" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Checks for the remote OpenSSH version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
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

b = get_backport_banner(banner:banner);

if(ereg(pattern:"SSH-.*-OpenSSH[-_]((1\.)|(2\.[0-1]))", string:b))
 {
  security_hole(port);
 }
