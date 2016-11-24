#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10274);
 script_bugtraq_id(952);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-2000-0113");
 
 script_name(english: "SyGate Backdoor");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote host." );
 script_set_attribute(attribute:"description", value:
"SyGate engine remote controller seems to be running on this port. 
It may be used by malicious users which are on the same subnet as this host
to reconfigure the remote SyGate engine." );
 script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this port." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english: "Detects whether SyGate remote controller is running");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english: "Backdoors");
 script_require_ports(7323);
 exit(0);
}

#
# The script code starts here
#

include('telnet_func.inc');
port = 7323;
if (get_port_state(port))
{
 banner = get_telnet_banner(port:port);
 if("yGate" >< banner)security_hole(port);
}
