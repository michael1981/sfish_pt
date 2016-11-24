#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(35711);
 script_version("$Revision: 1.4 $");
 script_name(english: "Universal Plug and Play (UPnP) Protocol Detection");

 script_set_attribute(attribute:"synopsis", value:"The remote device supports UPnP.");
 script_set_attribute(attribute:"description", value:
"The remote device answered to an SSDP M-SEARCH request. This means that
it supports 'Universal Plug and Play' aka UPnP. This protocol provides 
automatic configuration and device discovery. It is primiraly intended
for home networks.

Keep in mind that it could help an intruder discover your network 
architecture and speed an attack up.");
 script_set_attribute(attribute:"see_also", value: 
"http://en.wikipedia.org/wiki/Universal_Plug_and_Play
http://en.wikipedia.org/wiki/Simple_Service_Discovery_Protocol
http://quimby.gnus.org/internet-drafts/draft-cai-ssdp-v1-03.txt");
 script_set_attribute(attribute:"solution", value: "Filter access to this port if desired.");
 script_set_attribute(attribute:"risk_factor", value: "None");
 script_end_attributes();

 script_summary(english: "Sends a UPnP M-SEARCH request");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Service detection");
 exit(0);
}

include('global_settings.inc');
include('misc_func.inc');

####

if (TARGET_IS_IPV6) exit(0);
if (islocalhost()) exit(0);
if (! get_udp_port_state(1900)) exit(0);

if ( safe_checks() ) exit(0); # Switch issues

src = this_host();
dst = get_host_ip();
sport = rand() % (65536 - 1024) + 1024;

msearch =  strcat(
	'M-SEARCH * HTTP/1.1\r\n',
	'Host:239.255.255.250:1900\r\n',
	'ST:upnp:rootdevice\r\n',
	'Man:"ssdp:discover"\r\n',
	'MX:2\r\n',
	'\r\n');
len = strlen(msearch);

ip = forge_ip_packet(
        ip_hl:5, ip_v:4, ip_tos  :0,
        ip_len: 20, ip_id: rand(),
        ip_off  :0, ip_ttl  :64,
        ip_p: IPPROTO_UDP, ip_src: src);

udp = forge_udp_packet(
	ip: ip, uh_sport: sport, uh_dport: 1900,
        uh_ulen : 8 + len, data: msearch);

filt = strcat("udp and src ", dst, " and dst ", src, " and dst port ", sport);

u = NULL;
for (i = 0; i < 3 && ! u; i ++)
{
  r = send_packet(udp, pcap_active: TRUE, pcap_filter: filt);
  len = strlen(r);
  if (len > 28)
  {
    hl = ord(r[0]);
    if ((hl & 0xF0) == 0x40)
    {
      hl = (hl & 0xF) * 4;
      if (hl + 8 < len)
        u = substr(r, hl + 8);
    }
  }
}

if (! u) exit(0);

url = NULL;
r = egrep(string: u, pattern: '^LOCATION:', icase: 1);
if (r) url = strstr(chomp(r), 'http://');
if (url) set_kb_item(name: 'upnp/location', value: url);

e = strcat('\nThe device answered : \n\n', u);
set_kb_item(name: 'upnp/m-search', value: u);
register_service(port: 1900, ipproto: "udp", proto: "ssdp");
security_note(port: 1900, protocol: "udp", extra: e);
if (COMMAND_LINE) display(e);
