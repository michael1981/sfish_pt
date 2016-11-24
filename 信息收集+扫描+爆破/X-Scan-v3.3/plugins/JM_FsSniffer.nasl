#
# This script was written by Joseph Mlodzianowski <joseph@rapter.net>
# 
# 


include("compat.inc");

if(description)
{

script_id(11854);
script_version ("$Revision: 1.6 $");
name["english"] = "FsSniffer Detection";
script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"The remote host has been compromised." );
 script_set_attribute(attribute:"description", value:
"This host appears to be running FsSniffer on this port.

FsSniffer is backdoor which allows an intruder to steal
PoP3/FTP and other passwords you use on your system.

An attacker may use it to steal your passwords." );
 script_set_attribute(attribute:"solution", value:
"See http://www.nessus.org/u?10e4148e for details on removal" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N" );

script_end_attributes();


summary["english"] = "Determines the presence of FsSniffer";

script_summary(english:summary["english"]);

script_category(ACT_GATHER_INFO);


script_copyright(english:"This script is Copyright (C) 2003-2009 J.Mlodzianowski");
family["english"] = "Backdoors";
script_family(english:family["english"]);
script_dependencie("find_service2.nasl");
script_require_ports("Services/RemoteNC");
exit(0);
}


#
# The code starts here
#

port =  get_kb_item("Services/RemoteNC");
if(port)security_hole(port);
