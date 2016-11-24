#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(24333);
 script_version("$Revision: 1.8 $");

 script_cve_id("CVE-2006-5559");
 script_bugtraq_id(20704);
 script_xref(name:"OSVDB", value:"31882");

 name["english"] = "MS07-009: Vulnerability in Microsoft Data Access Components Could Allow Remote Code Execution (927779)";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web client." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the ADODB.Connection ActiveX control
which is vulnerable to a security flaw which may allow an attacker to execute
arbitrary code on the remote host by constructing a malicious web page and 
entice a victim to visit this web page." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms07-009.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 
 summary["english"] = "Checks the version of MDAC";

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


include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");


if ( hotfix_check_sp(xp:3, win2003:2, win2k:6) <= 0 ) exit(0);



if (is_accessible_share())
{
  path = hotfix_get_commonfilesdir() + '\\system\\ado\\';

 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"msado15.dll", version:"2.80.1064.0", path:path) ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"msado15.dll", version:"2.81.1128.0", path:path) ||
      hotfix_is_vulnerable (os:"5.0", file:"msado15.dll", version:"2.71.9054.0", min_version:"2.71.0.0", path:path)  ||
      hotfix_is_vulnerable (os:"5.0", file:"msado15.dll", version:"2.80.1064.0", min_version:"2.80.0.0", path:path)  ||
      hotfix_is_vulnerable (os:"5.0", file:"msado15.dll", version:"2.81.1128.0", min_version:"2.81.0.0", path:path)  ||
      hotfix_is_vulnerable (os:"5.0", file:"msado15.dll", version:"2.53.6307.0", path:path) )
 {
 set_kb_item(name:"SMB/Missing/MS07-009", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
}
