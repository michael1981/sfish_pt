#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(22193);
 script_version("$Revision: 1.12 $");

 script_cve_id("CVE-2006-3443", "CVE-2006-3648");
 script_bugtraq_id(19375, 19384);
 script_xref(name:"OSVDB", value:"27846");
 script_xref(name:"OSVDB", value:"27847");

 name["english"] = "MS06-051: Vulnerability in Windows Kernel Could Result in Remote Code Execution (917422)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"A local user can elevate his privileges on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the Windows kernel that may
allow a local user to elevate his privileges or to crash it (therefore
causing a denial of service)." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 2003:

http://www.microsoft.com/technet/security/bulletin/ms06-051.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
 summary["english"] = "Determines if hotfix 917422 has been installed";
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

if ( hotfix_check_sp(xp:3, win2k:6, win2003:2) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Kernel32.dll", version:"5.2.3790.556", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Kernel32.dll", version:"5.2.3790.2756", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Kernel32.dll", version:"5.1.2600.1869", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Kernel32.dll", version:"5.1.2600.2945", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Kernel32.dll", version:"5.0.2195.7099", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS06-051", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
