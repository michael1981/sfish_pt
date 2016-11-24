#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(24330);
 script_version("$Revision: 1.10 $");
 script_cve_id("CVE-2007-0211");
 script_bugtraq_id(22481);
 script_xref(name:"OSVDB", value:"31890");

 name["english"] = "MS07-006: Vulnerability in Windows Shell Could Allow Elevation of Privilege (928255)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Vulnerabilities in the Windows Shell may allow a user to elevate his
privileges." );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a version of the Windows Shell
which contains a vulnerability in the way it performs detection and
registration of new hardware.
An authenticated user may exploit this vulnerability to elevate his
privileges." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms07-006.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 summary["english"] = "Determines the presence of update 928255";

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


if ( hotfix_check_sp(xp:3, win2003:2) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"shell32.dll", version:"6.0.3790.630", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"shell32.dll", version:"6.0.3790.2867", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"shell32.dll", version:"6.0.2900.3051", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS07-006", value:TRUE);
 hotfix_security_hole();
 }
 hotfix_check_fversion_end(); 
}
