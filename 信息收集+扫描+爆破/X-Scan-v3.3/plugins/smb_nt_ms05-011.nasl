#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(16326);
 script_version("$Revision: 1.14 $");

 script_cve_id("CVE-2005-0045");
 script_bugtraq_id(12484);
 script_xref(name:"IAVA", value:"2005-t-0005");
 script_xref(name:"OSVDB", value:"13600");

 name["english"] = "MS05-011: Vulnerability in SMB may allow remote code execution (885250)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a flaw in the Server Message
Block (SMB) implementation that may allow an attacker to execute
arbitrary code on the remote host. 

To exploit this flaw, an attacker would need to send malformed
responses to the remote SMB client, and would be able to either
execute arbitrary code on the remote host or to perform a denial of
service." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 
2003 :

http://www.microsoft.com/technet/security/bulletin/MS05-011.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Determines if hotfix 885250 has been installed";
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
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Mrxsmb.sys", version:"5.2.3790.252", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Mrxsmb.sys", version:"5.1.2600.1620", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.2", sp:2, file:"Mrxsmb.sys", version:"5.1.2600.2598", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.0", file:"Mrxsmb.sys", version:"5.0.2195.7023", dir:"\system32\drivers") )
 {
 set_kb_item(name:"SMB/Missing/MS05-011", value:TRUE);
 security_hole(get_kb_item("SMB/transport"));
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else
{
 if ( ( hotfix_missing(name:"885250") > 0  ) &&
      ( hotfix_missing(name:"914389") > 0  ) )
 {
 set_kb_item(name:"SMB/Missing/MS05-011", value:TRUE);
 hotfix_security_hole();
 }
}
