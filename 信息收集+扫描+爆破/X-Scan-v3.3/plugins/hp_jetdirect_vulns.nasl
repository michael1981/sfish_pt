#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11396);
 script_version("$Revision: 1.4 $");
 script_bugtraq_id(7070);
 script_xref(name:"OSVDB", value:"57590");
 script_xref(name:"OSVDB", value:"57591");

 script_name(english:"HP JetDirect < Q.24.09 Multiple Vulnerabilities");
 script_summary(english:"Uses SNMP to determine if a flaw is present");

 script_set_attribute(attribute:"synopsis", value:
"The remote print server is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote hp jetdirect is, according to its version number,
vulnerable to an issue that may allow an attacker to
gain unauthorized access on this printer, or crash it." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?90d6acc0" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/hp/2003-q1/0058.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firmware Q.24.09 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();


 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 script_dependencie("snmp_sysDesc.nasl");
 script_require_keys("SNMP/community", "SNMP/sysDesc");
 exit(0);
}



os = get_kb_item("SNMP/sysDesc"); if(!os)exit(0);
if(egrep(pattern:"JETDIRECT.*Q\.24\.06", string:os, icase:TRUE))
  	security_warning(0);


