#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(24331);
 script_version("$Revision: 1.9 $");
 script_cve_id("CVE-2007-0210");
 script_bugtraq_id(22499);
 script_xref(name:"OSVDB", value:"31889");

 name["english"] = "MS07-007: Vulnerability in Windows Image Acquisition Service Could Allow Elevation of Privilege (927802)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Vulnerabilities in the Windows Acquisition Service may allow a user to 
elevate his privileges." );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a version of the Image Acquisition
service which contains a vulnerability in the way it starts applications.
An authenticated user may exploit this vulnerability to elevate his
privileges." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP :

http://www.microsoft.com/technet/security/bulletin/ms07-007.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 summary["english"] = "Determines the presence of update 927802";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


if ( hotfix_check_sp(xp:3) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", sp:2, file:"Wiaservc.dll", version:"5.1.2600.3051", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS07-007", value:TRUE);
 hotfix_security_hole();
 }
 hotfix_check_fversion_end(); 
}
else if ( hotfix_missing(name:"927802") > 0 ) {
 set_kb_item(name:"SMB/Missing/MS07-007", value:TRUE);
 hotfix_security_hole();
 }
