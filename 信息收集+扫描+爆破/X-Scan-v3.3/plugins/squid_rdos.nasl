#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
#  Ref: iDEFENSE 10.11.04
#
# This script is released under the GNU GPL v2
#

# Changes by Tenable:
# - Changed plugin family (7/06/09)
# - Updated to use compat.inc (11/20/2009)


include("compat.inc");

if(description)
{
 script_id(15463);
 script_version ("$Revision: 1.16 $");

 script_cve_id("CVE-2004-0918");
 script_bugtraq_id(11385);
 script_xref(name:"OSVDB", value:"10675");

 script_name(english:"Squid SNMP Module asn_parse_header() Function Remote DoS");

 script_set_attribute(attribute:"synopsis", value:
"The remote proxy server is prone to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"The remote Squid caching proxy, according to its version number, may
be vulnerable to a remote denial of service attack. 

This flaw is caused due to an input validation error in the SNMP
module, and exploitation requires that Squid not only was built to
support it but also configured to use it. 

An attacker can exploit this flaw to crash the server with a specially
crafted UDP packet. 

Note that Nessus reports this vulnerability using only the version
number in Squid's banner, so this might be a false positive." );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=152" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to squid 2.5.STABLE7 / squid 3.0.STABLE7 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P" );
script_end_attributes();

 
 script_summary(english:"Determines squid version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"Firewalls");
 script_dependencie("find_service1.nasl");
 if ( defined_func("bn_random") ) 
	script_dependencie("redhat-RHSA-2004-591.nasl");
 script_require_ports("Services/http_proxy",3128, 8080);
 exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


# nb: banner checks of open-source software are prone to false-
#     positives so only run the check if reporting is paranoid.
if (report_paranoia < 2) exit(0);


if ( get_kb_item("CVE-2004-0918") ) exit(0);

port = get_kb_item("Services/http_proxy");
if(!port)
{
 if(get_port_state(3128))
 { 
  port = 3128;
 }
 else port = 8080;
}

if(get_port_state(port))
{
  res = http_get_cache(item:"/", port:port);
  if(egrep(pattern:"[sS]quid/2\.([0-4]\.|5\.STABLE[0-6]([^0-9]|$))", string:res) ||
     egrep(pattern:"[sS]quid/3\.0\.(0|STABLE[1-6]([^0-9]|$))", string:res))
      security_warning(port);
}
