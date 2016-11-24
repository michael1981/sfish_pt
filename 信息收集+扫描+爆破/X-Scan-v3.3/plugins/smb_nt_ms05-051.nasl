#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(20004);
 script_version("$Revision: 1.13 $");

 script_cve_id("CVE-2005-2119", "CVE-2005-1978", "CVE-2005-1979", "CVE-2005-1980");
 script_bugtraq_id(15059, 15058, 15057, 15056);
 script_xref(name:"IAVA", value:"2005-A-0030");
 script_xref(name:"OSVDB", value:"18828");
 script_xref(name:"OSVDB", value:"19902");
 script_xref(name:"OSVDB", value:"19903");
 script_xref(name:"OSVDB", value:"19904");

 name["english"] = "MS05-051: Vulnerabilities in MSDTC and COM+ Could Allow Remote Code Execution (902400)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"A vulnerability in MSDTC and COM+ could allow remote code execution." );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a version of MSDTC and COM+
that is affected by several remote code execution, local privilege
escalation and denial of service vulnerabilities. 

An attacker may exploit these flaws to obtain the complete control of
the remote host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 
2003 :

http://www.microsoft.com/technet/security/bulletin/ms05-051.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Determines the presence of update 902400";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
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
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"ole32.dll", version:"5.2.3790.374", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"ole32.dll", version:"5.2.3790.2492", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"ole32.dll", version:"5.1.2600.1720", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"ole32.dll", version:"5.1.2600.2726", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0",       file:"ole32.dll", version:"5.0.2195.7059", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS05-051", value:TRUE);
 hotfix_security_hole();
 }
      hotfix_check_fversion_end(); 
}
