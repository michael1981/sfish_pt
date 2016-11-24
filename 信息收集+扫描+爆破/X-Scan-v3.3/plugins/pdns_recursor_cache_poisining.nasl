#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(34044);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2008-3217", "CVE-2008-1637");
 script_bugtraq_id(28517, 30782); 
 script_xref(name:"OSVDB", value:"43905");

 script_name(english:"PowerDNS Recursor DNS Predictable Transaction ID (TRXID) Cache Poisoning");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote DNS recursor is vulnerable to cache poisoning." );
 script_set_attribute(attribute:"description", value:
"The remote PowerDNS recursor is vulnerable to a cache poisoning
attack although it uses random source ports for the UDP queries.
Version below 3.1.6 rely upon the random() library function, which is
often implemented as a Linear Feedback Shift Register.
Such generators have good statistical properties and long cycle but
their internal state can be computed from few samples, so an attacker 
would thus be able to predict the next values." );
 script_set_attribute(attribute:"solution", value:
"Update to PowerDNS recursor 3.1.6." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english: "Checks PowerDNS recursor version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 script_family(english: "DNS");
 script_dependencies("pdns_version.nasl", "bind_version.nasl");
 script_require_keys("pdns/version");
 exit(0);
}

include("global_settings.inc");
include("dns_func.inc");
include("byte_func.inc");

if ( report_paranoia < 2 ) exit(0); 


ver = get_kb_item("pdns/version");
if (! ver)
{
 ver = get_kb_item("bind/version");
 if (! ver) exit(0);
}

if (ver =~ "^PowerDNS Recursor (3\.(0\.[0-9]|1\.[0-5])) ")
  security_hole(port: 53, proto: "udp");
