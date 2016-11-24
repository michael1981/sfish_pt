#
# (C) Tenable Network Security, Inc.
#
 
include("compat.inc");

if(description)
{
 script_id(33447);
 script_version ("$Revision: 1.11 $");
 script_cve_id("CVE-2008-1447");
 script_bugtraq_id(30131);
 script_xref(name:"OSVDB", value:"48186");
 script_xref(name:"OSVDB", value:"47510");
 script_xref(name:"OSVDB", value:"46837");
 script_xref(name:"OSVDB", value:"46786");
 script_xref(name:"OSVDB", value:"46776");
 script_xref(name:"OSVDB", value:"46777");
 # OSVDB split by vendor, 20 results as of 7/1/09. Including 6 higher profile vendors above.

 script_name(english:"Multiple Vendor DNS Query ID Field Prediction Cache Poisoning");

 script_set_attribute(attribute:"synopsis", value:
"The remote name resolver (or the server it uses upstream) may be vulnerable
to DNS cache poisoning." );
 script_set_attribute(attribute:"description", value:
"The remote DNS resolver does not use random ports when making queries to 
third party DNS servers.

This problem might be exploited by an attacker to poison the remote DNS 
server more easily, and therefore divert legitimate traffic to arbitrary
sites." );
 script_set_attribute(attribute:"see_also", value:"http://www.kb.cert.org/vuls/id/800113" );
 script_set_attribute(attribute:"solution", value:
"Contact your DNS server vendor for a patch" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:C" );
script_end_attributes();

 script_summary(english:"Determines if the remote DNS server uses random source ports when making queries"); 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 script_family(english: "DNS");
 script_dependencie("bind_query.nasl");
 script_require_keys("DNS/recursive_queries");
 exit(0);
}


include("global_settings.inc");
include("byte_func.inc");
include("dns_func.inc");
include("misc_func.inc");


NUM = 4;


function abs()
{
 local_var x;
 x = _FCT_ANON_ARGS[0];
 if ( x > 0 ) return x;
 return 0 - x;
}


for ( i = 0 ; i < NUM ; i ++ )
{
 req["transaction_id"] = rand() % 65535;
 req["flags"] = 0x0100;
 req["q"]     = 1;
 packet = mkdns(dns:req, query:mk_query(txt:dns_str_to_query_txt(rand_str(length:8, charset:"abcdefghijklmnopqrstuvwxyz")  + i + ".t.nessus.org."), type:0x0010, class:0x0001));
 soc = open_sock_udp(53); 
 send(socket:soc, data:packet);
 r = recv(socket:soc, length:4096);
 close(soc);
 if ( ! r ) exit(0);
 r = dns_split(r);
 res = r["an_rr_data_0_data"];
 if ( ! res || strlen(res) < 2  ) exit(0);
 res = substr(res, 1, strlen(res) - 1);
 if ( res !~ "^[0-9.]+,[0-9]+") exit(0);
 array = split(res, sep:",", keep:FALSE);
 responses_ip[i] = array[0];
 responses_ports[i] = int(array[1]);
}

for ( i = 1 ; i < NUM ; i ++ ) if ( responses_ip[i-1] != responses_ip[i]) exit(0);


for ( i = 1 ; i < NUM ; i ++ ) 
{
 x = responses_ports[i-1];
 y = responses_ports[i];
 if ( y < x ) y += 65535;
 if ( abs(responses_ports[i - 1] - responses_ports[i]) >= 20 ) exit(0);
}


report = 
"The ports used by " + responses_ip[0] + " are not random. 
An attacker may spoof DNS responses." + '\nList of used ports :\n';
for ( i = 0 ; i < NUM ; i ++ ) report += ' - ' + responses_ports[i] + '\n';

security_hole(port:53, proto: "udp", extra: report);
