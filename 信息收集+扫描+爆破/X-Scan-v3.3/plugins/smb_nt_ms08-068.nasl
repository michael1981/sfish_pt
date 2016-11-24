#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(34743);
 script_version("$Revision: 1.6 $");

 script_cve_id("CVE-2008-4037");
 script_bugtraq_id(7385);
 script_xref(name:"OSVDB", value:"49736");

 name["english"] = "MS08-068: Vulnerability in SMB Could Allow Remote Code Execution (957097)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to execute code on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a version of SMB (Server
Message Block) protocol which is vulnerable to a credentials
reflection attack. 

An attacker may exploit this flaw to elevate his privileges and gain
control of the remote host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
Vista and 2008 :

http://www.microsoft.com/technet/security/bulletin/ms08-068.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Determines the presence of update 957097";

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

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


if ( hotfix_check_sp(xp:4, win2003:3, win2k:6, vista:2) <= 0 ) exit(0);
if (is_accessible_share())
{
 if ( 
      hotfix_is_vulnerable (os:"6.0", sp:1, file:"Mrxsmb10.sys", version:"6.0.6001.22252", min_version:"6.0.6001.20000", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"6.0", sp:1, file:"Mrxsmb10.sys", version:"6.0.6001.18130", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"Mrxsmb10.sys", version:"6.0.6000.20904", min_version:"6.0.6000.20000", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"Mrxsmb10.sys", version:"6.0.6000.16738", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.2", sp:2, file:"Mrxsmb.sys", version:"5.2.3790.4369", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Mrxsmb.sys", version:"5.2.3790.3206", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.1", sp:3, file:"Mrxsmb.sys", version:"5.1.2600.5700", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Mrxsmb.sys", version:"5.1.2600.3467", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.0",       file:"Mrxsmb.sys", version:"5.0.2195.7174", dir:"\system32\drivers") )
 {
 set_kb_item(name:"SMB/Missing/MS08-068", value:TRUE);
 hotfix_security_hole();
 }
      hotfix_check_fversion_end(); 
}
