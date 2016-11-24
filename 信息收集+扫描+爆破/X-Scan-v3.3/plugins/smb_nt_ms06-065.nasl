#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(22538);
 script_version("$Revision: 1.7 $");
 script_cve_id("CVE-2006-4692");
 script_bugtraq_id(20318);
 script_xref(name:"OSVDB", value:"29424");

 name["english"] = "MS06-065: Vulnerability in Windows Object Packager Could Allow Remote Execution (924496)";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to execute code on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host runs a version of Windows which has a flaw in its Object
Packager.

The flaw may allow an attacker to execute code on the remote host.

To exploit this vulnerability, an attacker needs to entice a user to
visit a malicious web site." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-065.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 summary["english"] = "Checks the remote registry for 9224496";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
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


if ( hotfix_check_sp(xp:3, win2003:2) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Shdocvw.dll", version:"6.0.3790.588", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Shdocvw.dll", version:"6.0.3790.2783", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Shdocvw.dll", version:"6.0.2800.1892", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Shdocvw.dll", version:"6.0.2900.2987", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS06-065", value:TRUE);
 hotfix_security_warning();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
