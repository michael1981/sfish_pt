#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
# ref: ned <nd@felinemenace.org>
# This script is released under the GNU GPLv2

# Changes by Tenable:
# - Revised plugin title, output formatting (9/5/09)
# - Updated to use compat.inc (11/17/2009)


include("compat.inc");

if(description)
{
 script_id(12284);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-2004-0413");
 script_bugtraq_id(10519);
 script_xref(name:"OSVDB", value:"6935");
 script_xref(name:"GLSA", value:"GLSA 200406-07");
 script_xref(name:"SuSE", value:"SUSE-SA:2004:018");

 script_name(english:"Subversion < 1.0.5 svnserver svn:// Protocol Handler Remote Overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a
heap overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"A remote overflow exists in Subversion. svnserver fails to validate 
svn:// requests resulting in a heap overflow. With a specially 
crafted request, an attacker can cause arbitrary code execution 
resulting in a loss of integrity." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 1.0.5 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 script_summary(english:"Subversion SVN Protocol Parser Remote Integer Overflow");
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

if (egrep(string:r, pattern:".*subversion-1\.0\.[0-4][^0-9].*"))
{
	security_hole(port);
}

close(soc);
exit(0);
