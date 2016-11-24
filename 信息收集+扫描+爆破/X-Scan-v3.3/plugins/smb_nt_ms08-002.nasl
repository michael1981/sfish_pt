#
# (C) Tenable Network Security
#

include("compat.inc");

if(description)
{
 script_id(29894);
 script_version("$Revision: 1.8 $");

 script_cve_id("CVE-2007-5352");
 script_bugtraq_id(27099);
 script_xref(name:"OSVDB", value:"40071");

 name["english"] = "MS08-002: Vulnerability in LSASS Could Allow Local Elevation of Privilege (943485)";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Local users can elevate their privileges on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running version of Windows and LSASS which may
allow a local user to gain elevated privileged.

An attacker who has the ability to execute arbitrary commands on the remote
host may exploit this flaw to gain SYSTEM privileges." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms08-002.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 summary["english"] = "Checks the remote registry for KB943485";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");

if ( hotfix_check_sp(xp:3, win2k:6, win2003:3) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:1, file:"Lsasrv.dll", version:"5.2.3790.3041", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:2, file:"Lsasrv.dll", version:"5.2.3790.4186", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Lsasrv.dll", version:"5.1.2600.3249", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Lsasrv.dll", version:"5.0.2195.7147", dir:"\system32") )
   	 {
 set_kb_item(name:"SMB/Missing/MS08-002", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
