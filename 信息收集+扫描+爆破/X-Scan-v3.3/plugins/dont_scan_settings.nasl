#
# (C) Tenable Network Security, Inc.
#

# @PREFERENCES@


include("compat.inc");

if(description)
{
 script_id(22481);
 script_version ("$Revision: 1.6 $");

 script_name(english:"Do not scan fragile devices");

 script_set_attribute(attribute:"synopsis", value:
"This script offers a way to control scanning of fragile devices." );
 script_set_attribute(attribute:"description", value:
"This script offers a way to control scanning of certain categories of
network devices and hosts that are considered 'fragile' and might
crash if probed." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_end_attributes();

 script_family(english:"Settings");
 script_summary(english:"Define which type of hosts can or can not be scanned");
 script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
 script_category(ACT_INIT);

 script_add_preference(name:"Scan Network Printers", type:"checkbox", value:"no");
 script_add_preference(name:"Scan Novell Netware hosts", type:"checkbox", value:"no");
 exit(0);
}

set_kb_item(name:"/tmp/settings", value:TRUE);

opt = script_get_preference("Scan Network Printers");
if ( opt )
{
 if ( "yes" >< opt ) set_kb_item(name:"Scan/Do_Scan_Printers", value:TRUE);
}
else if ( safe_checks() == 0 ) set_kb_item(name:"Scan/Do_Scan_Printers", value:TRUE);


opt = script_get_preference("Scan Novell Netware hosts");
if ( opt )
{
 if ( "yes" >< opt ) set_kb_item(name:"Scan/Do_Scan_Novell", value:TRUE);
}
else if ( safe_checks() == 0 ) set_kb_item(name:"Scan/Do_Scan_Novell", value:TRUE);
