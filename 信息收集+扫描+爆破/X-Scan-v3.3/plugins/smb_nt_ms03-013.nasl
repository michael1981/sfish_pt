#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11541);
 script_version ("$Revision: 1.24 $");

 script_cve_id("CVE-2003-0112");
 script_bugtraq_id(7370);
 script_xref(name:"OSVDB", value:"9591");

 name["english"] = "MS03-013: Buffer overrun in NT kernel message handling (811493)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"A local user can elevate his privileges." );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows has a flaw in the way the kernel passes
error messages to a debugger.  An attacker could exploit it to gain
elevated privileges on this host. 

To successfully exploit this vulnerability, an attacker would need a
local account on this host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows NT, 2000 and XP :

http://www.microsoft.com/technet/security/bulletin/ms03-013.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Checks hotfix Q811493";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
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

if ( hotfix_check_sp(nt:7, win2k:4, xp:2) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", sp:1, file:"Ntkrnlmp.exe", version:"5.1.2600.1151", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"Ntkrnlmp.exe", version:"5.1.2600.108", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Ntkrnlmp.exe", version:"5.0.2195.6159", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"Ntkrnlmp.exe", version:"4.0.1381.7203", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"Ntkrnlmp.exe", version:"4.0.1381.33545", min_version:"4.0.1381.33000", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS03-013", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end();
 exit (0);
}
else 
if ( hotfix_missing(name:"811493") > 0 && 
     hotfix_missing(name:"840987") > 0 && 
     hotfix_missing(name:"885835") > 0 )
	{
	if ( hotfix_check_sp(xp:2) > 0  &&
	     hotfix_missing(name:"890859") == 0 ) exit(0);

	 {
 set_kb_item(name:"SMB/Missing/MS03-013", value:TRUE);
 hotfix_security_hole();
 }
	}

