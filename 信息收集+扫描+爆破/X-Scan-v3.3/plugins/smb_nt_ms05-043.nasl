#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(19406);
 script_version("$Revision: 1.16 $");
 script_cve_id("CVE-2005-1984");
 script_bugtraq_id(14514);
 script_xref(name:"IAVA", value:"2005-t-0029");
 script_xref(name:"OSVDB", value:"18607");

 name["english"] = "MS05-043: Vulnerability in Print Spooler Service Could Allow Remote Code Execution (896423)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host due to a flaw in the 
Spooler service." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the Print Spooler service which
is vulnerable to a security flaw which may allow an attacker to execute
code on the remote host or crash the spooler service.

An attacker can execute code on the remote host with a NULL session against :
- Windows 2000

An attacker can crash the remote service with a NULL session against :
- Windows 2000
- Windows XP SP1

An attacker needs valid credentials to crash the service against :
- Windows 2003
- Windows XP SP2" );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms05-043.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );



script_end_attributes();

 
 summary["english"] = "Determines the presence of update 896423";

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


if ( hotfix_check_sp(xp:3, win2003:1, win2k:6) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Spoolsv.exe", version:"5.2.3790.346", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Spoolsv.exe", version:"5.1.2600.1699", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Spoolsv.exe", version:"5.1.2600.2696", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", sp:4, file:"Spoolsv.exe", version:"5.0.2195.7054", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS05-043", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"896423") > 0 ) {
 set_kb_item(name:"SMB/Missing/MS05-043", value:TRUE);
 hotfix_security_hole();
 }
