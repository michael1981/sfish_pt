#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10640);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-1999-0103");
 script_xref(name:"OSVDB", value:"150");

 script_name(english:"Kerberos Server Spoofed Packet Amplification DoS (PingPong)");

 script_set_attribute(attribute:"synopsis", value:
"The remote service is vulnerable to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a Kerberos server which seems to be
vulnerable to a 'ping-pong' attack. 

When contacted on the UDP port, this service always responds, even to
malformed requests.  This makes it possible to involve it a
'ping-pong' attack, in which an attacker spoofs a packet between two
machines running this service, causing them to spew characters at each
other, slowing the machines down and saturating the network." );
 script_set_attribute(attribute:"see_also", value:"http://www.cert.org/advisories/CA-1996-01.html" );
 script_set_attribute(attribute:"solution", value:
"Disable this service if you do not use it." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C" );
script_end_attributes();


 script_summary(english:"Checks for the presence of a bad krb server");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 exit(0);
}
 

if(!get_udp_port_state(464))exit(0);

soc = open_sock_udp(464);
crp = crap(25);
if(soc)
{
 send(socket:soc, data:crp);
 r = recv(socket:soc, length:255);
 if(r){
	send(socket:soc, data:r);
	r = recv(socket:soc, length:255);
	if ( r ) security_hole(port:464, protocol:"udp");
     }
}
