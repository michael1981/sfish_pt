#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
 script_id(11052);
 script_version("$Revision: 1.19 $");
 script_cve_id("CVE-2002-2307");
 script_bugtraq_id(5279);
 script_xref(name:"OSVDB", value:"50544");

 script_name(english:"BenHur Firewall Source Port 20 ACL Restriction Bypass");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to bypass the firewall on the remote host." );
 script_set_attribute(attribute:"description", value:
"It is possible to connect to firewall-protected ports on the remote
host by setting the source port to 20. An attacker may use this 
flaw to access services that should not be accessible to outsiders 
on this host." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e608b229" );
 script_set_attribute(attribute:"solution", value:
"Update to 066 fix 2 or:

Reconfigure your firewall to reject any traffic coming from port 20." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N" );

script_end_attributes();


 script_summary(english:"Connects to a few services with sport = 20");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english:"Firewalls");
 exit(0);
}

include('global_settings.inc');

if(islocalhost() || NASL_LEVEL < 2204 )exit(0);

port = 8888;
	
soc = open_priv_sock_tcp(sport:20, dport:port);
if(soc){
	close(soc);
	soc = open_sock_tcp(port);
	if(soc){ close(soc); exit(0); }
	security_warning(port);
	}


