#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>

# See the Nessus Scripts License for details
#

include("compat.inc");

if(description)
{
 script_id(12266);
 script_version ("$Revision: 1.4 $");

 script_xref(name:"OSVDB", value:"20");

 script_name(english:"W32.Dabber Worm Detection");
 script_summary(english:"W32.Dabber worm detection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has been compromised." );
 script_set_attribute(attribute:"description", value:
"The W32.Dabber worm is listening on this port.  W32.Dabber propagates
by exploiting a vulnerability in the FTP server component of
W32.Sasser.Worm and its variants. 

It installs a backdoor on infected hosts and tries to listen on port
9898.  If the attempt fails, it tries to listen on ports 9899 through
9999 in sequence until it finds an open port." );
 script_set_attribute(attribute:"see_also", value:
"http://securityresponse.symantec.com/avcenter/venc/data/w32.dabber.b.html");
 script_set_attribute(attribute:"see_also", value:
"http://www.microsoft.com/technet/security/bulletin/MS04-011.mspx");
 script_set_attribute(attribute:"solution", value:
"- Disable access to port 445 and Dabber remote shell by using a firewall.
- Apply Microsoft MS04-011 patch.
- Update your virus definitions." );
 script_set_attribute(attribute:"cvss_vector", value:
"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_attribute(attribute:"plugin_publication_date", value:
"2004/06/10");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 family["english"] = "Backdoors";
 script_family(english:family["english"]);
 script_dependencies("find_service2.nasl");
 script_require_ports(5554);
 exit(0);
}

#
# The script code starts here
#
sasser_port = 5554;    
dabber_ports = make_list();

for ( port = 9898 ; port <= 9999 ; port ++ ) 
{
	dabber_ports = make_list(dabber_ports, port);
}

if (get_port_state(sasser_port))
{
	if (open_sock_tcp(sasser_port)) 
	{		
		foreach port (dabber_ports)
		{
			if (get_port_state(port)) 
			{	
				soc=open_sock_tcp(port);
				if (soc)
				{
					buf = string("C");
					send(socket:soc, data:buf);
					data_root = recv(socket:soc, length:2048);
				        close(soc);

					if(data_root)
  					{
						security_hole(port);
					}
				}
			}
		}
	}
}
exit(0);
