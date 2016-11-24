#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(18022);
 script_version("$Revision: 1.14 $");

 script_cve_id("CVE-2005-0060", "CVE-2005-0061", "CVE-2005-0550", "CVE-2005-0551");
 script_bugtraq_id(13109, 13110, 13115, 13121);
 script_xref(name:"OSVDB", value:"15459");
 script_xref(name:"OSVDB", value:"15460");
 script_xref(name:"OSVDB", value:"15461");
 script_xref(name:"OSVDB", value:"15462");

 name["english"] = "MS05-018: Vulnerabilities in Windows Kernel (890859)";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"A local user can elevate his privileges on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the Windows kernel which is vulnerable
to a security flaw which may allow a local user to elevate his privileges
or to crash the remote host (therefore causing a denial of service)." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 2003:

http://www.microsoft.com/technet/security/bulletin/ms05-018.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 summary["english"] = "Checks the remote registry for 890859";

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

include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");


if ( hotfix_check_sp(xp:3, win2k:5, win2003:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Authz.dll", version:"5.2.3790.274", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Authz.dll", version:"5.1.2600.1634", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Authz.dll", version:"5.1.2600.2622", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Authz.dll", version:"5.0.2195.7028", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS05-018", value:TRUE);
 security_hole(get_kb_item("SMB/transport"));
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else
{
 if ( hotfix_missing(name:"890859") > 0 )
 {
 set_kb_item(name:"SMB/Missing/MS05-018", value:TRUE);
 hotfix_security_hole();
 }
}
