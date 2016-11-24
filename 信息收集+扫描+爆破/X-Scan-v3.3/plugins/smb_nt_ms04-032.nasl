#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(15457);
 script_version("$Revision: 1.19 $");

 script_cve_id(
  "CVE-2004-0207", 
  "CVE-2004-0208", 
  "CVE-2004-0209", 
  "CVE-2004-0211"
 );
 script_bugtraq_id(11365, 11369, 11375, 11378);
 script_xref(name:"IAVA", value:"2004-A-0017");
 script_xref(name:"OSVDB", value:"10690");
 script_xref(name:"OSVDB", value:"10691");
 script_xref(name:"OSVDB", value:"10692");
 script_xref(name:"OSVDB", value:"10693");

 name["english"] = "MS04-032: Security Update for Microsoft Windows (840987)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is missing a security update for Microsoft Windows
(840987).  The missing security update fixes issues in the following
areas :

  - Window Management
  - Virtual DOS Machine
  - Graphics Rendering Engine
  - Windows Kernel

A local attacker may exploit any of these vulnerabilities to cause a
local denial of service or obtain higher privileges on the remote
host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows NT, 2000, XP and
2003 :

http://www.microsoft.com/technet/security/bulletin/ms04-032.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Determines if hotfix 840987 has been installed";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
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

if ( hotfix_check_sp(nt:7, win2k:5, xp:2, win2003:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Win32k.sys", version:"5.2.3790.198", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Win32k.sys", version:"5.1.2600.1581", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"Win32k.sys", version:"5.1.2600.166", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Win32k.sys", version:"5.0.2195.6966", dir:"\system32") || 
      hotfix_is_vulnerable (os:"4.0", file:"Win32k.sys", version:"4.0.1381.7292", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"Win32k.sys", version:"4.0.1381.33580", min_version:"4.0.1381.33000", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS04-032", value:TRUE);
 security_hole(get_kb_item("SMB/transport"));
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"840987") > 0  )
{
   	# Superseed by MS05-018
	if ( hotfix_check_sp(win2003:1) > 0 &&
	     hotfix_missing(name:"890859") < 0 ) exit(0);

	 {
 set_kb_item(name:"SMB/Missing/MS04-032", value:TRUE);
 hotfix_security_hole();
 }
}

