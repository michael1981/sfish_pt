#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(12053);
 script_version ("$Revision: 1.5 $");
 
 script_name(english:"Host Fully Qualified Domain Name (FQDN) Resolution");
 script_summary(english:"Performs a name resolution");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "It was possible to resolve the name of the remote host."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:"Nessus was able to resolve the FQDN of the remote host."
 );
 script_set_attribute(
   attribute:"solution", 
   value:"n/a"
 );
 script_set_attribute(
   attribute:"risk_factor", 
   value:"None"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"General");
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");

 exit(0);
}


if ( get_host_name() != get_host_ip() )
{
 if ( defined_func("report_xml_tag") )
 {
	report_xml_tag(tag:"host-fqdn", value:get_host_name());
	report_xml_tag(tag:"host-ip", value:get_host_ip());
 }
 report = string("\n", get_host_ip(), " resolves as ", get_host_name(), ".\n");
 security_note(port:0, extra:report);
}
