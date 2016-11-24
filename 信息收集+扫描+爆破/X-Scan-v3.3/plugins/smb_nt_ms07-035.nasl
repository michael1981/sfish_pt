#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(25488);
 script_version("$Revision: 1.8 $");

 script_cve_id("CVE-2007-2219");
 script_bugtraq_id(24370);
 script_xref(name:"OSVDB", value:"35341");

 name["english"] = "MS07-035: Vulnerability in Win 32 API Could Allow Remote Code Execution (935839)";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the Win32
API." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the Win32 API which is
vulnerable to a security flaw that may allow a local user to elevate
his privileges, and might allow a remote attacker to execute arbitrary
code on this host. 

To exploit this flaw, an attacker would need to find a way to misuse
the Win32 API.  One way of doing so would be to lure a user on the
remote host into visiting a specially crafted web page." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms07-035.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 summary["english"] = "Determines if hotfix 935839 has been installed";

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

if ( hotfix_check_sp(xp:3, win2k:6, win2003:3) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:2, file:"Kernel32.dll", version:"5.2.3790.4062", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Kernel32.dll", version:"5.2.3790.2919", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Kernel32.dll", version:"5.1.2600.3119", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Kernel32.dll", version:"5.0.2195.7135", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS07-035", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}

