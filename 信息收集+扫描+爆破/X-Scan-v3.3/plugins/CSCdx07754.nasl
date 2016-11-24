#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Script License for details
#
# Thanks to Nicolas FISCHBACH (nico@securite.org) for his help
#
# Ref:  http://www.cisco.com/warp/public/707/vpn3k-multiple-vuln-pub.shtml



include("compat.inc");

if(description)
{
 script_id(11293);
 script_bugtraq_id(5614, 5617);
 script_version("$Revision: 1.9 $");
 script_cve_id("CVE-2002-1100","CVE-2002-1098");
 script_xref(name:"OSVDB", value:"8913");
 script_xref(name:"OSVDB", value:"8922");

 script_name(english:"Cisco VPN 3000 Concentrator Multiple Vulnerabilities (CSCdx07754, CSCdx24622, CSCdx24632)");

 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote VPN concentrator is subject to multiple flaws :

- XML public rule
- HTML pages access
- HTML login processing

This vulnerability is documented as Cisco bug ID CSCdx07754, 
CSCdx24622 and CSCdx24632" );
 script_set_attribute(attribute:"solution", value:
"http://www.cisco.com/warp/public/707/vpn3k-multiple-vuln-pub.shtml" );
 script_set_attribute(attribute:"risk_factor", value:"Medium" );
 script_end_attributes();


 summary["english"] = "Uses SNMP to determine if a flaw is present";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is (C) 2003-2009 Tenable Network Security, Inc.");

 script_family(english:"CISCO");

 script_dependencie("snmp_sysDesc.nasl");
 script_require_keys("SNMP/community",
			  "SNMP/sysDesc",
			  "CISCO/model");
 script_require_ports("Services/www", 80);
 exit(0);
}



# The code starts here
ok=0;

os = get_kb_item("SNMP/sysDesc"); if(!os)exit(0);

port = get_kb_list("Services/www");
if(isnull(port)) 
{
 if(!get_port_state(80))exit(0);
 soc = open_sock_tcp(80);
 if(!soc)exit(0);
 else close(soc);
}



# Is this a VPN3k concentrator ?
if(!egrep(pattern:".*VPN 3000 Concentrator.*", string:os))exit(0);

# < 3.5.3
if(egrep(pattern:".*Version 3\.5\.Rel.*", string:os))ok = 1;
if(egrep(pattern:".*Version 3\.5\.[0-2].*", string:os))ok = 1;

# 3.1.x
if(egrep(pattern:".*Version 3\.1\..*", string:os))ok = 1;

# 3.0.x
if(egrep(pattern:".*Version 3\.0\..*", string:os))ok = 1;

# 2.x.x
if(egrep(pattern:".*Version 2\..*", string:os))ok = 1;


if(ok)security_warning(port:161, proto:"udp");
