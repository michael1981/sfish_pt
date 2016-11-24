#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if(description)
{
 script_id(10504);
 script_bugtraq_id(1651);
 script_xref(name:"OSVDB", value:"403");
 script_version ("$Revision: 1.25 $");
 script_cve_id("CVE-2000-0851");

 name["english"] = "MS00-065: Still Image Service Privilege Escalation patch (272736)";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"A local user can elevate his privileges." );
 script_set_attribute(attribute:"description", value:
"The hotfix for the 'Still Image Service Privilege Escalation'
problem has not been applied.

This vulnerability allows a malicious user, who has the
right to log on this host locally, to gain additional privileges
on this host." );
 script_set_attribute(attribute:"solution", value:
"http://www.microsoft.com/technet/security/bulletin/ms00-065.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Determines whether the hotfix Q272736 is installed";
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

if ( hotfix_check_sp(win2k:1) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q272736") > 0 )
	 {
 set_kb_item(name:"SMB/Missing/MS00-065", value:TRUE);
 hotfix_security_hole();
 }
