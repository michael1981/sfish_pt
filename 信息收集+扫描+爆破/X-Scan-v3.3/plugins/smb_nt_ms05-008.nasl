#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(16324);
 script_version("$Revision: 1.13 $");

 script_cve_id("CVE-2005-0053");
 script_bugtraq_id(11466);
 script_xref(name:"OSVDB", value:"13608");

 name["english"] = "MS05-008: Vulnerability in Windows Shell (890047)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web
client." );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a flaw in the Windows Shell
that may allow an attacker to elevate his privileges and/or execute
arbitrary code on the remote host. 

To exploit this flaw, an attacker would need to lure a victim into
visiting a malicious website or opening a malicious file attachment." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 
2003 :

http://www.microsoft.com/technet/security/bulletin/ms05-008.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Determines if hotfix 890047 has been installed";
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

if ( hotfix_check_sp(win2k:5, xp:3, win2003:1) <= 0 ) exit(0);


if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Shell32.dll", version:"6.0.3790.241", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Shell32.dll", version:"6.0.2800.1613", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:2, file:"Shell32.dll", version:"6.0.2900.2578", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Shell32.dll", version:"5.0.3900.7009", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS05-008", value:TRUE);
 security_hole(get_kb_item("SMB/transport"));
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else
{
 if ( hotfix_missing(name:"890047") > 0  &&
      hotfix_missing(name:"893086") > 0  &&
      hotfix_missing(name:"908531") > 0  &&
      hotfix_missing(name:"921398") > 0  &&
      hotfix_missing(name:"900725") > 0 )
 {
 set_kb_item(name:"SMB/Missing/MS05-008", value:TRUE);
 hotfix_security_hole();
 }
}
