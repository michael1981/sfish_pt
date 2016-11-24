#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(25886);
 script_version("$Revision: 1.11 $");

 script_cve_id("CVE-2007-1749");
 script_bugtraq_id(25310);
 script_xref(name:"OSVDB", value:"36390");

 name["english"] = "MS07-050: Vulnerability in Vector Markup Language Could Allow Remote Code Execution (938127)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the email
client or the web browser." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Internet Explorer or Outlook
Express with a bug in the Vector Markup Language (VML) handling
routine that may allow an attacker execute arbitrary code on the
remote host by sending a specially crafted email or by luring a user
on the remote host into visiting a rogue web site." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003 and
Vista :

http://www.microsoft.com/technet/security/Bulletin/MS07-050.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 
 summary["english"] = "Determines the presence of update 938127";

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

dir = hotfix_get_commonfilesdir();
if (isnull(dir))
  exit (0);


if ( hotfix_check_sp(xp:4, win2003:3, win2k:6, vista:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"6.0", sp:0, file:"Vgx.dll", version:"7.0.6000.16513", dir:"\Microsoft Shared\VGX", path:dir) ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"Vgx.dll", version:"7.0.6000.20628", min_version:"7.0.6000.20000", dir:"\Microsoft Shared\VGX", path:dir) ||
      hotfix_is_vulnerable (os:"5.2", sp:1, arch:"x86", file:"Vgx.dll", version:"6.0.3790.2963", dir:"\Microsoft Shared\VGX", path:dir) ||
      hotfix_is_vulnerable (os:"5.2", sp:2, arch:"x86", file:"Vgx.dll", version:"6.0.3790.4107", dir:"\Microsoft Shared\VGX", path:dir) ||
      hotfix_is_vulnerable (os:"5.2", sp:2, arch:"x86", file:"Vgx.dll", version:"6.0.3790.4106", dir:"\Microsoft Shared\VGX", path:dir) ||
      hotfix_is_vulnerable (os:"5.2", file:"Vgx.dll", version:"7.0.6000.20628", min_version:"7.0.0.0", dir:"\Microsoft Shared\VGX", path:dir) ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Vgx.dll", version:"6.0.2900.3164", dir:"\Microsoft Shared\VGX", path:dir) ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Vgx.dll", version:"7.0.6000.20628", min_version:"7.0.0.0", dir:"\Microsoft Shared\VGX", path:dir) ||
      hotfix_is_vulnerable (os:"5.1", sp:3, file:"Vgx.dll", version:"7.0.6000.20628", min_version:"7.0.0.0", dir:"\Microsoft Shared\VGX", path:dir) ||
      hotfix_is_vulnerable (os:"5.0", file:"Vgx.dll", version:"6.0.2800.1599", min_version:"6.0.0.0", dir:"\Microsoft Shared\VGX", path:dir) ||
      hotfix_is_vulnerable (os:"5.0", file:"Vgx.dll", version:"5.0.3854.2500", dir:"\Microsoft Shared\VGX", path:dir) )
 {
 set_kb_item(name:"SMB/Missing/MS07-050", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
