#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# See the Nessus Scripts License for details
#
# This script is released under the GNU GPLv2
#
# MA 2008-02-26: I cleaned the message and the code.


include("compat.inc");

if(description)
{
 script_id(12252);
 script_version ("$Revision: 1.8 $");
 script_name(english: "Korgo Worm Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is probably infected with Korgo worm." );
 script_set_attribute(attribute:"description", value:
"Nessus found that TCP ports 113 and 3067 are open.
The Korgo worm is known to open a backdoor on these ports.
It propagates by exploiting the LSASS vulnerability on TCP port 445 
(as described in Microsoft Security Bulletin MS04-011)

** Note that Nessus did not try to talk to the backdoor,
** so this might be a false positive." );
 script_set_attribute(attribute:"see_also", value:"http://securityresponse.symantec.com/avcenter/venc/data/w32.korgo.c.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.microsoft.com/technet/security/bulletin/MS04-011.mspx" );
 script_set_attribute(attribute:"solution", value:
"- Disable access to port 445 by using a firewall
- Apply Microsoft MS04-011 patch." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
 
script_end_attributes();

 
 script_summary(english: "Look at ports 113 and 3067 (Korgo backdoor)");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english: "Backdoors");
 #script_dependencies("find_service1.nasl");
 script_require_ports(113, 3067);
 exit(0);
}

#
# The script code starts here
#
ports =  make_list(3067, 113);

foreach p (ports)
{
 if (! get_port_state(p))
  exit(0);
}

foreach p (ports)
{
 s = open_sock_tcp(p);
 if (! s) exit(0);
 close(s);
}

security_hole(port: ports[0]);
