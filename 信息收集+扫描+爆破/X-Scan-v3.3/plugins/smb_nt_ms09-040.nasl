#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(40559);
 script_version("$Revision: 1.2 $");

 script_cve_id("CVE-2009-1922");
 script_bugtraq_id(35969);
  script_xref(name:"OSVDB", value:"56901");

 script_name(english:"MS09-040: Vulnerability in Message Queuing Could Allow Elevation of Privilege (971032)");
 script_summary(english:"Determines if hotfix 971032 has been installed");
 
 script_set_attribute(attribute:"synopsis", value:
"Users can elevate their privileges on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows is affected by a vulnerability in the
Microsoft Message Queuing Service (MSMQ). 

An attacker with valid logon credentials may exploit this flaw to execute 
arbitrary code on the remote host with the SYSTEM privileges and therefore
elevate his privileges." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003
and Vista :

http://www.microsoft.com/technet/security/bulletin/ms09-040.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C" );

 script_set_attribute(
  attribute:"patch_publication_date", 
  value:"2009/08/11"
 );
 script_set_attribute(
  attribute:"plugin_publication_date", 
  value:"2009/08/11"
 );
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows : Microsoft Bulletins");

 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 
 script_dependencies("smb_hotfixes.nasl" );
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");

if ( hotfix_check_sp(win2k:6, xp:3, win2003:3, vista:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.0", file:"Mqqm.dll", version:"5.0.0.808", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Mqqm.dll", version:"5.1.0.1111", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:2, file:"Mqqm.dll", version:"5.2.2007.4530", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"Mqqm.dll", version:"6.0.6000.16871", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"Mqqm.dll", version:"6.0.6000.21068", min_version:"6.0.6000.21000", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS09-040", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
