#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(29308);
 script_version("$Revision: 1.8 $");

 script_cve_id("CVE-2007-3901", "CVE-2007-3895");
 script_bugtraq_id(26804);
 script_xref(name:"OSVDB", value:"39126");
 script_xref(name:"OSVDB", value:"39127");

 name["english"] = "MS07-064: Vulnerabilities in DirectX Could Allow Remote Code Execution (941568)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"A vulnerability in DirectX could allow remote code execution." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of DirectX that is vulnerable to a
remote code execution attack. 

To exploit this flaw, an attacker would need to send a malformed AVI,
WMV or SAMI file to a user on the remote host and have him open it." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003 and
Vista :

http://www.microsoft.com/technet/security/bulletin/ms07-064.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 summary["english"] = "Determines the presence of update 941568";

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


if ( hotfix_check_sp(xp:3, win2003:3, win2k:6, vista:1) <= 0 ) exit(0);
dvers = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/DirectX/Version");
if ( !dvers ) exit(0);

if (is_accessible_share())
{
 if ( 
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"quartz.dll", version:"6.6.6000.16587", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"quartz.dll", version:"6.6.6000.20710", min_version:"6.6.6000.20000", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:2, file:"quartz.dll", version:"6.5.3790.4178", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"quartz.dll", version:"6.5.3790.3035", min_version:"6.5.3790.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"quartz.dll", version:"6.5.2600.3243", min_version:"6.5.2600.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"quartz.dll", version:"6.1.9.733", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"quartz.dll", version:"6.3.1.890", min_version:"6.3.0.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"quartz.dll", version:"6.5.1.908", min_version:"6.5.1.0", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS07-064", value:TRUE);
 hotfix_security_hole();
 }
 hotfix_check_fversion_end(); 
}
