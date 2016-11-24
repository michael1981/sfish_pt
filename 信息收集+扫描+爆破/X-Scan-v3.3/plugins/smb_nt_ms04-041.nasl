#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(15966);
 script_version("$Revision: 1.12 $");

 script_cve_id("CVE-2004-0571", "CVE-2004-0901");
 script_bugtraq_id(11927, 11929);
 script_xref(name:"OSVDB", value:"12373");
 script_xref(name:"OSVDB", value:"12375");

 name["english"] = "MS04-041: Vulnerabilities in WordPad (885836)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through WordPad." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of Microsoft WordPad that is
vulnerable to two security flaws. 

To exploit these flaws an attacker would need to send a malformed Word
file to a victim on the remote host and wait for him to open the file
using WordPad. 

Opening the file with WordPad will trigger a buffer overflow that may
allow an attacker to execute arbitrary code on the remote host with
the privileges of the user." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows NT, 2000, XP and
2003 :

http://www.microsoft.com/technet/security/bulletin/ms04-041.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Checks the remote registry for MS04-041";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
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

if ( hotfix_check_sp(nt:7, xp:3, win2k:5, win2003:1) <= 0 ) exit(0);


if (is_accessible_share())
{
 path = hotfix_get_programfilesdir() + "\Windows NT\Accessories";

 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Wordpad.exe", version:"5.2.3790.224", path:path) ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Wordpad.exe", version:"5.1.2600.1606", path:path) ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Mswrd6.wpc", version:"10.0.803.2", path:path) ||
      hotfix_is_vulnerable (os:"5.0", file:"Wordpad.exe", version:"5.0.2195.6991", path:path) || 
      hotfix_is_vulnerable (os:"4.0", file:"Wordpad.exe", version:"4.0.1381.7312", path:path) )
 {
 set_kb_item(name:"SMB/Missing/MS04-041", value:TRUE);
 security_hole(get_kb_item("SMB/transport"));
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"885836") > 0 )
	 {
 set_kb_item(name:"SMB/Missing/MS04-041", value:TRUE);
 hotfix_security_hole();
 }
