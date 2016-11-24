#
# This script was written by deepquest <deepquest@code511.com>
# 
# See the Nessus Scripts License for details
#
# Modifications by rd:
# -  added ref: http://www.cert.org/advisories/CA-2002-32.html
# -  removed leftovers in the code (send(raw_string(0, 0))
# -  added the use of telnet_init()
# -  replaced open_sock_udp by open_sock_tcp()
# -  added script id
# -  attributed copyright properly to deepquest
# -  merged some ideas from Georges Dagousset <georges.dagousset@alert4web.com> 
#    who wrote a duplicate of this script
#
#----------
# XXXX Untested!


include("compat.inc");

if(description)
{
 script_id(11170);
 script_bugtraq_id(6220);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-2002-1272");
 script_xref(name:"OSVDB", value:"15411");

 script_name(english:"Alcatel OmniSwitch 7700/7800 Switches Backdoor Access");
 script_summary(english:"Checks for the presence of backdoor in Alcatel 7700/7800 switches");

 script_set_attribute(attribute:"synopsis", value:
"The remote switch has a backdoor installed." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be a backdoored Alcatel OmniSwitch 7700/7800.

An attacker can gain full access to any device running AOS version
5.1.1, which can result in, but is not limited to, unauthorized
access, unauthorized monitoring, information leakage, or denial of
service." );
 script_set_attribute(attribute:"see_also", value:"http://www.cert.org/advisories/CA-2002-32.html" );
 script_set_attribute(attribute:"solution", value:
"Block access to port 6778/TCP or update to AOS 5.1.1.R02 or AOS
5.1.1.R03." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (c) 2002-2009 deepquest");
 family["english"] = "Backdoors";
 script_family(english:family["english"]);
 script_dependencie("find_service1.nasl");
 script_require_ports(6778);
 exit(0);
}


include("global_settings.inc");
include("telnet_func.inc");
include("misc_func.inc");

port = 6778;
p = known_service(port:port);
if(p && p != "telnet" && p != "aos")exit(0);



if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  data = get_telnet_banner(port:port);
 if(data)
  {
  security_hole(port:port,extra:string("The banner:\n",data,"\nshould be reported to deraison@nessus.org\n"));
  register_service(port: port, proto: "aos");
  }
 }
}
