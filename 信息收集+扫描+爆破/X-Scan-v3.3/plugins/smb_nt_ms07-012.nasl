#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(24336);
 script_version("$Revision: 1.12 $");
 script_cve_id("CVE-2007-0025");
 script_bugtraq_id(22476);
 script_xref(name:"OSVDB", value:"31887");

 name["english"] = "MS07-012: Vulnerability in Microsoft MFC Could Allow Remote Code Execution (924667)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the MFC
component provided with Microsoft Windows." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of Microsoft Windows which has a vulnerability 
in the the MFC component which could be abused by an attacker to execute arbitrary 
code on the remote host.

To exploit this vulnerability, an attacker would need to spend a specially
crafted RTF file to a user on the remote host and lure him into opening it." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/Bulletin/MS07-012.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 
 summary["english"] = "Determines the presence of update 924667";

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



include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");

if ( hotfix_check_sp(xp:3, win2003:3, win2k:6) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:2, arch:"x64", file:"wmfc40u.dll", version:"4.1.0.6141", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, arch:"x64", file:"wmfc40u.dll", version:"4.1.0.6141", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:2, arch:"x86", file:"Mfc40u.dll", version:"4.1.0.6141", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, arch:"x86", file:"Mfc40u.dll", version:"4.1.0.6141", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Mfc40u.dll", version:"4.1.0.6141", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Mfc40u.dll", version:"4.1.0.6141", dir:"\system32") )
   	 {
 set_kb_item(name:"SMB/Missing/MS07-012", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end();
 exit (0);
}
