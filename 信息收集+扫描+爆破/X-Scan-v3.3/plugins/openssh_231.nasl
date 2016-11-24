#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10608);
 script_version ("$Revision: 1.18 $");

 script_cve_id("CVE-2001-1585");
 script_bugtraq_id(2356);
 script_xref(name:"OSVDB", value:"504");

 script_name(english:"OpenSSH 2.3.1 SSHv2 Public Key Authentication Bypass");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a
authentication bypass vulnerability." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running OpenSSH 2.3.1.

This version is vulnerable to a flaw which allows any attacker who can
obtain the public key of a valid SSH user to log into this host
without any authentication." );
 script_set_attribute(attribute:"see_also", value:"http://www.openbsd.org/advisories/ssh_bypass.txt" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH 2.3.2" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	
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

banner = get_kb_item("SSH/banner/" + port);
if ( ! banner ) exit(0);
banner = tolower(get_backport_banner(banner:banner));

if ( ereg(pattern:"OpenSSH.2\.3\.1([^0-9]|$)", string:banner, icase:TRUE ) )
 security_hole(port);
