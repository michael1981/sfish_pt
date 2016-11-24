#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10509);
 script_bugtraq_id(1304);
 script_xref(name:"OSVDB", value:"408");
 script_version ("$Revision: 1.25 $");

 script_cve_id("CVE-2000-0544");
 name["english"] = "MS00-066: Malformed RPC Packet patch (272303)";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to crash the remote host." );
 script_set_attribute(attribute:"description", value:
"The hotfix for the 'Malformed RPC Packet' problem has not been
applied. 

This vulnerability allows a malicious user, to cause a denial of
service against this host." );
 script_set_attribute(attribute:"solution", value:
"http://www.microsoft.com/technet/security/bulletin/ms00-066.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C" );

script_end_attributes();

 
 summary["english"] = "Determines whether the hotfix Q272303 is installed";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}



include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

if ( hotfix_check_sp(win2k:2) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q272303") > 0 )
	 {
 set_kb_item(name:"SMB/Missing/MS00-066", value:TRUE);
 hotfix_security_hole();
 }

