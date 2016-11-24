#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
# ref: Subversion team July 2004
# This script is released under the GNU GPLv2

# Changes by Tenable:
# - Revised plugin title, output formatting (9/5/09)
# - Updated to use compat.inc (11/17/2009)


include("compat.inc");

if(description)
{
 script_id(13848);
 script_version ("$Revision: 1.9 $");
 script_cve_id("CVE-2004-1438");
 script_bugtraq_id(10800);
 script_xref(name:"OSVDB", value:"8239");

 script_name(english:"Subversion < 1.0.6 mod_authz_svn Restricted File Access Bypass");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that may allow access to
restricted files." );
 script_set_attribute(attribute:"description", value:
"You are running a version of Subversion which is older than 
1.0.6.

A flaw exist in older version, in the apache module mod_authz_svn.
An attacker can access to any file in a given subversion repository,
no matter what restrictions have been set by the administrator." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to subversion 1.0.6 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english:"Check for Subversion version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"Misc.");
 script_dependencie("subversion_detection.nasl");
 script_require_ports("Services/subversion");
 exit(0);
}



# start check
# mostly horked from MetaSploit Framework subversion overflow check

port = get_kb_item("Services/subversion");
if ( ! port ) port = 3690;

if (! get_tcp_port_state(port))
	exit(0);

dat = string("( 2 ( edit-pipeline ) 24:svn://host/svn/nessusr0x ) ");

soc = open_sock_tcp(port);
if (!soc)
        exit(0);

r = recv_line(socket:soc, length:1024);

if (! r)
	exit(0);

send(socket:soc, data:dat);
r = recv_line(socket:soc, length:256);

if (! r)
	exit(0);

#display(r);

if (egrep(string:r, pattern:".*subversion-1\.0\.[0-5][^0-9].*"))
{
	security_warning(port);
}

close(soc);
exit(0);
