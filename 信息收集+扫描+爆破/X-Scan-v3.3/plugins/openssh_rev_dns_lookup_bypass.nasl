#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11712);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2003-0386");
 script_bugtraq_id(7831);
 script_xref(name:"OSVDB", value:"2112");
 
 script_name(english:"OpenSSH < 3.6.2 Reverse DNS Lookup Bypass");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by DNS
lookup bypass vulnerability." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host appears to be running
OpenSSH-portable version 3.6.1 or older.

There is a flaw in such version which may allow an attacker to
bypass the access controls set by the administrator of this server.

OpenSSH features a mechanism which can restrict the list of
hosts a given user can log from by specifying a pattern
in the user key file (ie: *.mynetwork.com would let a user
connect only from the local network).

However there is a flaw in the way OpenSSH does reverse DNS lookups.
If an attacker configures his DNS server to send a numeric IP address
when a reverse lookup is performed, he may be able to circumvent
this mechanism." );
 script_set_attribute(attribute:"see_also", value:"http://www.kb.cert.org/vuls/id/978316" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH 3.6.2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	
script_end_attributes();

 script_summary(english:"Checks for the remote SSH version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
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
if(ereg(pattern:".*openssh[-_]((1\..*)|(2\..*)|(3\.([0-5][^0-9]|6(\.[01])?$)))", string:banner)) security_warning(port);
