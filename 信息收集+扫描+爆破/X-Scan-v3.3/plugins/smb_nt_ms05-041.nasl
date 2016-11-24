#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(19404);
 script_version("$Revision: 1.14 $");
 script_cve_id("CVE-2005-1218");
 script_bugtraq_id(14259);
 script_xref(name:"IAVA", value:"2005-t-0026");
 script_xref(name:"OSVDB", value:"18624");

 name["english"] = "MS05-041: Vulnerability in Remote Desktop Protocol Could Allow Denial of Service (899591)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to crash the remote desktop service." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the Remote Desktop protocol/service
which is vulnerable to a security flaw which may allow an attacker to crash
the remote service and cause the system to stop responding." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms05-041.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C" );



script_end_attributes();

 
 summary["english"] = "Determines the presence of update 899591";

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
if ( hotfix_check_sp(win2k:6) > 0)
{
 if ( hotfix_check_nt_server() <= 0 ) 
   exit(0); 
} 

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Rdpwd.sys", version:"5.2.3790.348", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Rdpwd.sys", version:"5.2.3790.2465", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Rdpwd.sys", version:"5.1.2600.1698", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Rdpwd.sys", version:"5.1.2600.2695", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.0", sp:4, file:"Rdpwd.sys", version:"5.0.2195.7055", dir:"\system32\drivers") )
 {
 set_kb_item(name:"SMB/Missing/MS05-041", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
