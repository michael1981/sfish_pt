#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(35375);
 script_version("$Revision: 1.4 $");
 script_cve_id("CVE-2008-5277");
 script_bugtraq_id(32627);
 script_xref(name:"OSVDB", value:"50458");

 script_name(english:"PowerDNS CH HINFO Query Handling DoS");

 script_set_attribute(attribute:"synopsis", value:
"The remote DNS may be vulnerable to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"According to its version, the remote PowerDNS server may be vulnerable
to a denial of service attack when processing specially crafted CH
HINFO queries. 

Note that successful exploitation requires that the DNS server run in
an uncommon and non-standard configuration to be affected (single
threaded)." );
 script_set_attribute(attribute:"see_also", value:"http://doc.powerdns.com/powerdns-advisory-2008-03.html" );
 script_set_attribute(attribute:"solution", value:
"Either remove the 'distributor-threads=1' option from 'pdns.conf' or
upgrade to PowerDNS version 2.9.21.2 or 2.9.22." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 
 script_summary(english:"Checks PowerDNS version");
 script_category(ACT_GATHER_INFO); 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "DNS");
 script_dependencie("pdns_version.nasl");
 script_require_keys("pdns/version");
 exit(0);
}

include("global_settings.inc");

if (paranoia_level < 2) exit(0);

ver = get_kb_item("pdns/version");
if ("POWERDNS" >!< ver) exit(0);

if (ereg(string: ver, pattern: "POWERDNS 2\.9\.(1?[0-9]|20|21(\.[01])?) "))
  security_warning(port: 53, proto:"udp");
