#
# (C) Tenable Network Security, Inc.
#
# Added some extra checks. Axel Nennker axel@nennker.de 20020301


include("compat.inc");

if(description)
{
 script_id(10409);
 script_version ("$Revision: 1.21 $");

 script_xref(name:"OSVDB", value:"20");
 script_name(english: "SubSeven Trojan Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has been compromised." );
 script_set_attribute(attribute:"description", value:
"This host seems to be running SubSeven on this port.
SubSeven is a Trojan Horse which allows an intruder to take the control 
of the remote computer.

An attacker may use it to steal your passwords, modify your data, and 
preventing you from working properly." );
 script_set_attribute(attribute:"solution", value:
"Reinstall your system." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 script_summary(english: "Determines the presence of SubSeven");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english: "Backdoors");
 script_dependencie("find_service2.nasl");
 script_require_ports("Services/subseven");
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/subseven");
if (port) security_hole(port);
