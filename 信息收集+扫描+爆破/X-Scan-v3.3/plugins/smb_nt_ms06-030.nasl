#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(21692);
 script_version("$Revision: 1.11 $");
 script_cve_id("CVE-2006-2373", "CVE-2006-2374");
 script_bugtraq_id(18356, 18357);
 script_xref(name:"OSVDB", value:"26439");
 script_xref(name:"OSVDB", value:"26440");

 name["english"] = "MS06-030: Vulnerability in Server Message Block Could Allow Elevation of Privilege (914389)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to execute code on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a version of SMB (Server
Message Block) protocol that is affected by several vulnerabilities. 

An attacker may exploit these flaws to elevate his privileges and gain
control of the remote host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 
2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-030.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Determines the presence of update 914389";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
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


if ( hotfix_check_sp(xp:3, win2003:2, win2k:6) <= 0 ) exit(0);
if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Mrxsmb.sys", version:"5.2.3790.529", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Mrxsmb.sys", version:"5.2.3790.2697", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Mrxsmb.sys", version:"5.1.2600.1836", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Mrxsmb.sys", version:"5.1.2600.2902", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.0",       file:"Mrxsmb.sys", version:"5.0.2195.7097", dir:"\system32\drivers") )
 {
 set_kb_item(name:"SMB/Missing/MS06-030", value:TRUE);
 hotfix_security_hole();
 }
      hotfix_check_fversion_end(); 
}
