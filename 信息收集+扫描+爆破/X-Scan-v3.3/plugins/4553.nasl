#
# This script was written by Chris Gragsone
# This script is for finding hosts that are running the 4553 parasite "mothership"
#


include("compat.inc");

if(description) {
	script_id(11187);
 script_set_attribute(attribute:"synopsis", value:
"The remote host has been compromised." );
 script_set_attribute(attribute:"description", value:
"The backdoor software '4553' seems to be installed on this 
host, which indicates it has been compromised." );
 script_set_attribute(attribute:"solution", value:
"re-install this host" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	
	script_version("$Revision: 1.8 $");
	# script_cve_id("CVE-MAP-NOMATCH");
	# NOTE: no CVE id assigned (jfs, december 2003)
	script_name(english:"4553 Parasite Mothership Backdoor Detection");
script_end_attributes();

	script_summary(english:"Detects the presence of 4553 parasite's mothership");
	script_category(ACT_GATHER_INFO);
	script_copyright(english:"This script is (C) 2002-2009 Violating");
	script_family(english:"Backdoors");
	script_require_ports(21227, 21317);
	
	exit(0);
}



targets = make_list(21227, 21317);
foreach target (targets)
{
 if(get_port_state(target)) 
 {
 soc = open_sock_tcp(target);
 if(!soc)exit(0);
 send(socket:soc, data:"-0x45-");
 data = recv(socket:soc, length:1024);

 if(("0x53" >< data) || ("<title>UNAUTHORIZED-ACCESS!</title>" >< data)) 
  {
	security_hole(target);
  }
 }
}
