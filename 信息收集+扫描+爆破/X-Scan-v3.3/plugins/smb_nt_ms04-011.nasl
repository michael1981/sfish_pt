#
# (C) Tenable Network Security
#



include("compat.inc");

if(description)
{
 script_id(12205);
 script_version("$Revision: 1.25 $");

 script_cve_id(
  "CVE-2003-0533", "CVE-2003-0663", "CVE-2003-0719", "CVE-2003-0806",
  "CVE-2003-0906", "CVE-2003-0907", "CVE-2003-0908", "CVE-2003-0909",
  "CVE-2003-0910", "CVE-2004-0117", "CVE-2004-0118", "CVE-2004-0119", 
  "CVE-2004-0121"
 );
 script_bugtraq_id(10111, 10113, 10117, 10119, 10122, 10124, 10125);
 script_xref(name:"IAVA", value:"2004-A-0006");
 script_xref(name:"OSVDB", value:"5254");
 script_xref(name:"OSVDB", value:"5255");
 script_xref(name:"OSVDB", value:"5259");

 name["english"] = "MS04-011: Microsoft Hotfix (credentialed check) (835732)";

 script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is missing a critical Microsoft Windows Security Update (835732).

This update fixes various flaws which may allow an attacker to execute arbitrary code
on the remote host.

A series of worms (Sasser) are known to exploit this vulnerability in the 
wild." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows NT, 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms04-011.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Checks for ms04-011");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

#

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

if ( hotfix_check_sp(nt:7, win2k:5, xp:2, win2003:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Lsasrv.dll", version:"5.2.3790.134", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Lsasrv.dll", version:"5.1.2600.1361", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"Lsasrv.dll", version:"5.1.2600.134", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Lsasrv.dll", version:"5.0.2195.6902", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"Winsrv.dll", version:"4.0.1381.7260", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS04-011", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"KB835732") > 0 ) 
	 {
 set_kb_item(name:"SMB/Missing/MS04-011", value:TRUE);
 hotfix_security_hole();
 }
 
