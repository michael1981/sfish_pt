#
# (C) Tenable Network Security, Inc.
#

if ( NASL_LEVEL < 3210 ) exit(0);



include("compat.inc");

if(description)
{
 script_id(33813);
 script_version ("$Revision: 1.4 $");

 script_name(english: "Port scanner dependency");
 
 script_set_attribute(attribute:"synopsis", value:
"Portscanners stub." );
 script_set_attribute(attribute:"description", value:
"This plugin is an internal dependency used by several Nessus scripts. 
It does not perform anything by itself." );
 script_set_attribute(attribute:"solution", value:
"N/A" );
 script_set_attribute(attribute:"risk_factor", value:"None" );


script_end_attributes();

 
 script_summary(english: "Used for the re-ordering of several scanners");
 script_category(ACT_SETTINGS);	
 
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 script_family(english: "Settings");
 script_dependencies("ping_host.nasl", "wmi_netstat.nbin", "netstat_portscan.nasl", "snmpwalk_portscan.nasl");
 exit(0);
}

exit(0);
