#TRUSTED 30eaacc02bc9af6f5ab7bbcc913bfcce3dc93dce8078e0c6fabb4d1dff84dc923d5f768d6f92ba3a84f56cb4ab75aac1de0ec934269829ec7393a088521e61cf8447120b2aa5ce4b6e8e2f47b2dd6f46e86dcdf73f0b8e1a7dbf0340bc459e5fa185d4cb69acdec9c2a049b2d87ce090aa0470e840f69d46acf499d88d8e64355d81d115f46ca52ffb53e8771b148a2744728337ae2fe5c6174d96438c5a6c7db94dbf9aee85d746c3ad8960df6d2be1cb986da9ea6aedf03ac2cc8b20b6b56cfccd42f0876383c5a704a36c9549729034dcc4835632bc082817f58cc5298c9573f1ba5ae975c4c065b32d21a960598ebb97754e174b1d6c1ee9a6e0319ca01a2d28dbea5efcc5eaa50b33a4bdaea7f86dea45fbe26bc00a5b4f1ebef260eed32263064a8786710435d3d5af6f5b82cfa3aa6b5b684f2916937c145b7f700705c9b2c60286b80e24b8db3801395b037eddfc761489ceca07f9e30db088611480e31fdc30564f5fb8e2fcb4ac5d648c661e0b1df79d64a1b647d5916460ec659c02b093ba341e90e92c7972fe84768ac3f7e599657456e45c1328761dbc1e8331d804fe7dd04cef54c5c0573b338fc53ca8bb6c4b2774c29d61701a88b0afcef1100202ee554ba6a009f86068484bf1412cedcec125dc52c6ae58b9b6570c54b198a56988baa8abe5da0387834c82920b58c0521eea412e7adf44c8a0f7418e37
#
# (C) Tenable Network Security, Inc.
#

if (! defined_func("get_local_mac_addr")) exit(0);
if (! defined_func("inject_packet")) exit(0);
include("compat.inc");

if(description)
{
 script_id(35713);
 script_version("1.2");
 script_name(english: "Scan for UPnP hosts (multicast)");

 script_set_attribute(attribute:"synopsis", value:"This machine is a UPnP client.");
 script_set_attribute(attribute:"description", value:
"This machine answered to a multicast UPnP NOTIFY packet by trying to 
fetch the XML description that Nessus advertised.");
 script_set_attribute(attribute:"risk_factor", value: "None");
 script_end_attributes();

 script_summary(english: "Multicast a UPnP NOTIFY multicast");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Service detection");
 script_exclude_keys("/tmp/UDP/1900/closed");
 exit(0);
}

global_var debug_level;
include('misc_func.inc');
include('byte_func.inc');

if (! get_kb_item("Host/udp_scanned") &&
    ! get_kb_item("global_settings/thorough_tests") ) exit(0);

if ( TARGET_IS_IPV6 ) exit(0);	# TBD

if ( safe_checks() ) exit(0); # Switch issues
if (islocalhost()) exit(0);
if (!islocalnet())exit(0);
if (! get_udp_port_state(1900) || get_kb_item("/tmp/UDP/1900/closed")) exit(0);
if (! service_is_unknown(port: 1900, ipproto: "udp")) exit(0);

myaddr = this_host();
dstaddr = get_host_ip();
returnport = rand() % 32768 + 32768;

data = strcat(
'NOTIFY * HTTP/1.1\r\n',
'HOST: 239.255.255.250:1900\r\n',
'CACHE-CONTROL: max-age=1800\r\n',
'LOCATION: http://', myaddr, ':', returnport, '/gatedesc.xml\r\n',
'NT: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n',
'NTS: ssdp:alive\r\n',
'SERVER: Linux/2.6.26-hardened-r9, UPnP/1.0, Portable SDK for UPnP devices/1.6.6\r\n',
'X-User-Agent: redsonic\r\n',
'USN: uuid:75802409-bccb-40e7-8e6c-fa095ecce13e::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n',
'\r\n' );

len = strlen(data);

ip = forge_ip_packet(ip_hl: 5, ip_v: 4, ip_tos: 0, ip_len: 20,
   ip_id: rand(), ip_off: 0, ip_ttl: 64, ip_p: IPPROTO_UDP,
   ip_src: myaddr, ip_dst: '239.255.255.250');

udp = forge_udp_packet(ip: ip, uh_sport: rand() % 32768 + 32768, uh_dport: 1900,
 uh_ulen :8 + len, data: data);
if ( defined_func("datalink") ) 
{
 if ( datalink() != DLT_EN10MB ) exit(0);
}

macaddr   = get_local_mac_addr();

ethernet = '\x01\x00\x5E\x7F\xFF\xFA'	# Multicast address
	 + macaddr
	 + mkword(0x0800)		# Protocol = IPv4
	 + udp;
filter = strcat("tcp and src ", dstaddr, " and dst port ", returnport);

for (i = 0; i < 60; i ++)
{
  r = inject_packet(packet: ethernet, filter:filter, timeout: 1);
  if (strlen(r) > 14 + 20 + 20)
  {
    flags = get_tcp_element(tcp: substr(r, 14), element:"th_flags");
    if (flags & TH_SYN)
    {
       security_note(port:1900,protocol:"udp");
       register_service(port: 1900, proto: "upnp-client", ipproto: "udp");
    }
    exit(0);     
  }
}
