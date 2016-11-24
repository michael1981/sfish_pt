#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(17631);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2005-0876", "CVE-2005-0877");
 script_bugtraq_id(12897);
 script_xref(name:"OSVDB", value:"15000");
 script_xref(name:"OSVDB", value:"15001");
 
 script_name(english:"dnsmasq < 2.21.0 Multiple Remote Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote DNS / DHCP service is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running dnsmasq, a DHCP and DNS server. 

The version of dnsmasq installed on the remote host contains an
off-by-one boundary error when reading a DHCP lease file.  An attacker
can leverage this issue to cause the application to crash or possible
execute arbitrary code the next time it is restarted by sending a long
hostname and client-id when requesting a DHCP lease. 

In addition, the application only checks the 16-bit ID against current
queries when receiving DNS replies.  An attacker may be able to send a
flood of DNS replies and poison the DNS cache." );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/advisories/14691" );
 script_set_attribute(attribute:"see_also", value:"http://www.thekelleys.org.uk/dnsmasq/CHANGELOG" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to dnsmasq 2.21.0 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_summary(english:"Checks the version of dnsmasq"); 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english: "DNS");
 script_dependencie("bind_version.nasl");
 script_require_keys("bind/version");
 exit(0);
}

include("global_settings.inc");

if (report_paranoia < 2) exit(0);

# dnsmasq replies to BIND.VERSION
vers = get_kb_item("bind/version");
if ( vers && ereg(pattern:"dnsmasq-([01]\.|2\.([0-9]$|1[0-9]$|20))", string:vers) )
	security_hole(port:53, proto:"udp");
