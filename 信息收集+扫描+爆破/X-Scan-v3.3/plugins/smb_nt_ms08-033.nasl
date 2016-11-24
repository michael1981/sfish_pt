#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(33135);
 script_version("$Revision: 1.5 $");

 script_cve_id("CVE-2008-0011", "CVE-2008-1444");
 script_bugtraq_id(29578, 29581);
 script_xref(name:"OSVDB", value:"46064");
 script_xref(name:"OSVDB", value:"46065");

 name["english"] = "MS08-033: Vulnerabilities in DirectX Could Allow Remote Code Execution (951698)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"A vulnerability in DirectX could allow remote code execution." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of DirectX that is affected by a
remote code execution vulnerability. 

To exploit this flaw, an attacker would need to send a specially
malformed MPEG or SAMI file to a user on the remote host and have him
open it." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
Vista and 2008 :

http://www.microsoft.com/technet/security/bulletin/ms08-033.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 summary["english"] = "Determines the presence of update 951698";

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
      hotfix_is_vulnerable (os:"6.0", sp:1, file:"quartz.dll", version:"6.6.6001.18063", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:1, file:"quartz.dll", version:"6.6.6001.22167", min_version:"6.6.6000.20000", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"quartz.dll", version:"6.6.6000.16681", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"quartz.dll", version:"6.6.6000.20823", min_version:"6.6.6000.20000", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:2, file:"quartz.dll", version:"6.5.3790.4283", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"quartz.dll", version:"6.5.3790.3130", min_version:"6.5.3790.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:3, file:"quartz.dll", version:"6.5.2600.5596", min_version:"6.5.2600.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"quartz.dll", version:"6.5.2600.3367", min_version:"6.5.2600.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"quartz.dll", version:"6.1.9.734", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"quartz.dll", version:"6.3.1.891", min_version:"6.3.0.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"quartz.dll", version:"6.5.1.909", min_version:"6.5.1.0", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS08-033", value:TRUE);
 hotfix_security_hole();
 }
 hotfix_check_fversion_end(); 
}
