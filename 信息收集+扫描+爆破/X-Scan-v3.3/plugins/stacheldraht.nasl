#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10270);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-2000-0138");
 script_xref(name:"OSVDB", value:"20");
 script_xref(name:"OSVDB", value:"295");
 name["english"] = "Stacheldraht Detection";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has been compromised." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running Stacheldraht, a Trojan Horse that
can be used to control your system or make it attack another network.

It is very likely that this host has been compromised" );
 script_set_attribute(attribute:"solution", value:
"Restore your system from backups, contact CERT and your local authorities" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english: "Detects the presence of Stacheldraht");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english: "Backdoors");
 script_require_keys("Settings/ThoroughTests");
 exit(0);
}


include('global_settings.inc');
if ( TARGET_IS_IPV6 ) exit(0);
if ( islocalhost() ) exit(0);
if ( ! thorough_tests ) exit(0);

src = this_host();
ip = forge_ip_packet(	ip_v : 4,	ip_hl : 5,
			ip_tos : 0,	ip_id : 0x1234,
			ip_len : 20,	ip_off : 0,
			ip_p : IPPROTO_ICMP,
			ip_src : src,	ip_ttl : 0x40);
			
icmp = forge_icmp_packet(ip:ip, icmp_type:0, icmp_code : 0,
			 icmp_seq : 1, icmp_id : 668, 
			 data : "gesundheit!");
			 
filter = string("icmp and src host ", 
		get_host_ip(), 
		" and dst host ", 
		this_host());
		 
r = send_packet(icmp, pcap_active:TRUE, pcap_filter:filter);
if(r)
{
 type = get_icmp_element(icmp:r, element:"icmp_id");
 if(type == 669)security_hole(port:0, protocol:"icmp");
}
