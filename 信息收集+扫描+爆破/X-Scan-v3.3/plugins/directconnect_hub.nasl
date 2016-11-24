#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# This script is released under the GNU GPLv2

# Changes by Tenable:
# - Revised plugin title (9/3/09)

include("compat.inc");

if(description)
{
  script_id(13751);
  script_version ("$Revision: 1.8 $");
 
  script_name(english:"Direct Connect Hub Detection");
  script_summary(english:"Direct Connect hub detection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a peer-to-peer filesharing application.");
 script_set_attribute(attribute:"description", value:
"A Direct Connect 'hub' (or server) is running on this port.  Direct
Connect is a protocol used for peer-to-peer file-sharing as well as
chat, and a hub routes communications among peers.  While any type of
file may be shared, Direct Connect hubs often handle movies, images,
music files, and games, which may not be suitable for use in a
business environment.");
 script_set_attribute(attribute:"see_also", value:
"http://en.wikipedia.org/wiki/Direct_connect_file-sharing_application");
 script_set_attribute(attribute:"solution", value:
"Make sure that use of this program agrees with your organization's
acceptable use and security policies.");
 script_set_attribute(attribute:"risk_factor", value:
"None");
 script_set_attribute(attribute:"plugin_publication_date", value:
"2004/07/25");
 script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
  script_family(english:"Peer-To-Peer File Sharing");
  script_dependencie("find_service1.nasl");
  script_require_ports("Services/DirectConnectHub", 411);
  exit(0);
}



port = get_kb_item("Services/DirectConnectHub");
if (!port) port = 411;
if (!get_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if(soc)
{
	r=recv_line(socket:soc, length:1024);
	if ( ! r ) exit(0);
	if (ereg(pattern:"^\$Lock .+",string:r))
	{
		# Disconnect nicely.
		str="$quit|";
		send(socket:soc,data:str);

		security_note(port);
	}
	close(soc);
}
