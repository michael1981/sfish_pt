#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11197);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-2003-0001");
 script_bugtraq_id(6535);
 script_xref(name:"OSVDB", value:"3873");
 
 script_name(english:"Multiple Ethernet Driver Frame Padding Information Disclosure (Etherleak)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host leaks memory in network packets." );
 script_set_attribute(attribute:"description", value:
"The remote host is vulnerable to an 'Etherleak' - the remote ethernet
driver seems to leak bits of the content of the memory of the remote
operating system. 

Note that an attacker may take advantage of this flaw only when its
target is on the same physical subnet." );
 script_set_attribute(attribute:"see_also", value:"http://www.atstake.com/research/advisories/2003/a010603-1.txt" );
 script_set_attribute(attribute:"solution", value:
"Contact your vendor for a fix" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english:"etherleak check");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 exit(0);
}

#
# The script code starts here
#
##include("dump.inc");

if ( ! islocalnet() ) exit(0);
if ( TARGET_IS_IPV6 ) exit(0);

function probe()
{
 local_var filter, i, icmp, ip, len, rep, str;

 ip     = forge_ip_packet(ip_p:IPPROTO_ICMP, ip_src:this_host());
 icmp   = forge_icmp_packet(ip:ip, icmp_type:8, icmp_code:0, icmp_seq:1, icmp_id:1, data:"x");

 filter = string("icmp and src host ", get_host_ip(), " and dst host ", this_host());

 for(i=0;i<3;i++)
 {
 rep = send_packet(icmp, pcap_filter:filter);
 if(rep)break;
 }

 if(rep == NULL)exit(0);
##dump(dtitle: "ICMP", ddata: rep);

 len = get_ip_element(ip:rep, element:"ip_len");
 if(strlen(rep) > len)
 {
 str="";
 for(i=len;i<strlen(rep);i++)
  {
   str = string(str, rep[i]);
  }
  return(str);
 }
 else return(NULL);
}

function ping()
{
 local_var filter, i, icmp, ip, rep;

 ip     = forge_ip_packet(ip_p:IPPROTO_ICMP, ip_src:this_host());
 icmp   = forge_icmp_packet(ip:ip, icmp_type:8, icmp_code:0, icmp_seq:1, icmp_id:1, data:crap(data:"nessus", length:254));

 filter = string("icmp and src host ", get_host_ip(), " and dst host ", this_host());

 for(i=0;i<3;i++) rep = send_packet(icmp, pcap_filter:filter, pcap_timeout:1);
}

if(islocalhost())exit(0);


if(islocalnet())
{
 str1 = probe();
 ping();
 sleep(1);
 str2 = probe();

##dump(dtitle: "ether1", ddata: str1);
##dump(dtitle: "ether2", ddata: str2);

 if(isnull(str1) || isnull(str2))exit(0);

 if( str1 != str2 ){
		security_warning(proto:"icmp", port:0);
		set_kb_item(name:"Host/etherleak", value:TRUE);
	}
}
