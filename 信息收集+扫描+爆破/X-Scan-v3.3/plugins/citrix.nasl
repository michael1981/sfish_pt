# This script was written by John Lampe ... j_lampe@bellsouth.net
#
# Script is based on 
# Citrix Published Application Scanner version 2.0
# By Ian Vitek, ian.vitek@ixsecurity.com
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
 script_id(11138);
 script_bugtraq_id(5817);
 script_xref(name:"OSVDB", value:"50617");
 script_version ("$Revision: 1.12 $");
 script_name(english:"Citrix Published Applications Remote Enumeration");

 script_set_attribute(attribute:"synopsis", value:
"The remote Citrix service is affected by an information disclosure 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"It is possible for a remote attacker to enumerate published
applications that are allowed on the affected Citrix server." );
 script_set_attribute(attribute:"see_also", value:"http://sh0dan.org/oldfiles/hackingcitrix.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2002-09/0330.html" );
 script_set_attribute(attribute:"solution", value:
"Consult the advisory referenced above for tips about securing the
service." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();


 summary["english"] = "Find Citrix published applications";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);


 script_copyright(english:"This script is Copyright (C) 2002-2008 John Lampe...j_lampe@bellsouth.net");
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 exit(0);
}


#script code starts here

port = 1604;
trickmaster =               raw_string(0x20,0x00,0x01,0x30,0x02,0xFD,0xA8,0xE3);
trickmaster = trickmaster + raw_string(0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00);
trickmaster = trickmaster + raw_string(0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00);
trickmaster = trickmaster + raw_string(0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00);

get_pa =          raw_string(0x2A,0x00,0x01,0x32,0x02,0xFD);
get_pa = get_pa + raw_string(0xa8,0xe3,0x00,0x00,0x00,0x00);
get_pa = get_pa + raw_string(0x00,0x00,0x00,0x00,0x00,0x00);
get_pa = get_pa + raw_string(0x00,0x00,0x00,0x00,0x00,0x00);
get_pa = get_pa + raw_string(0x00,0x00,0x00,0x00,0x21,0x00);
get_pa = get_pa + raw_string(0x02,0x00,0x00,0x00,0x00,0x00);
get_pa = get_pa + raw_string(0x00,0x00,0x00,0x00,0x00,0x00);

if(!get_udp_port_state(port))exit(0);

soc = open_sock_udp(port);
if (soc) {
    send (socket:soc, data:trickmaster);
    incoming = recv(socket:soc, length:1024);
    close(soc);
    if (incoming) {
	soc = open_sock_udp(port);
        send(socket:soc, data:get_pa);
	incoming = recv(socket:soc, length:1024);
	if(incoming) security_warning(port:port, proto:"udp");
    }
}

