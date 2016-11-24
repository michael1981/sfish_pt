#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(12230);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2004-0426");
 script_bugtraq_id(10247);
 script_xref(name:"OSVDB", value:"5731");
 
 script_name(english:"rsync Traversal Arbitrary File Creation");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary files may be overwritten on the remote host" );
 script_set_attribute(attribute:"description", value:
"The remote rsync server might be vulnerable to a path traversal
issue.

An attacker may use this flaw to gain access to arbitrary files hosted
outside of a module directory." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to rsync 2.6.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N" );

 script_end_attributes();

 script_summary(english:"Determines if rsync is running");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Misc.");
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_dependencies("rsync_modules.nasl");
 script_require_ports("Services/rsync", 873);
 exit(0);
}

port = get_kb_item("Services/rsync");
if(!port)port = 873;
if(!get_port_state(port))exit(0);

welcome = get_kb_item("rsync/" + port + "/banner");
if ( ! welcome )
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 welcome = recv_line(socket:soc, length:4096);
 close(soc);
 if(!welcome)exit(0);
}


if(ereg(pattern:"@RSYNCD: (1[0-9]|2[0-7])[^0-9]", string:welcome))
{
 security_warning(port);
}
