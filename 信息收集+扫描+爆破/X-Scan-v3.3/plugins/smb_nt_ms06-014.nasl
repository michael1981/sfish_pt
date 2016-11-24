#
# (C) Tenable Network Security
#

include("compat.inc");

if(description)
{
 script_id(21211);
 script_version("$Revision: 1.9 $");
 script_cve_id("CVE-2006-0003");
 script_bugtraq_id(17462);
 script_xref(name:"OSVDB", value:"24517");

 name["english"] = "MS06-014: Vulnerability in MDAC Could Allow Code Execution (911562)";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"A local administrator may elevate his privileges on the remote host, through a
flaw in the MDAC server." );
 script_set_attribute(attribute:"description", value:
"The remote Microsoft Data Access Component (MDAC) server is vulnerable to a 
flaw which may allow a local administrator to elevate his privileges to the
'system' level, thus gaining the complete control over the remote system." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-014.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );


script_end_attributes();

 
 summary["english"] = "Checks the version of MDAC";

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


include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");


if ( hotfix_check_sp(xp:3, win2003:2, win2k:6) <= 0 ) exit(0);



if (is_accessible_share())
{
 path = hotfix_get_commonfilesdir() + '\\system\\msadc\\';
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"msadco.dll", version:"2.80.1062.0", path:path) ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"msadco.dll", version:"2.82.2644.0", path:path) ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"msadco.dll", version:"2.71.9053.0", path:path) ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"msadco.dll", version:"2.81.1124.0", path:path) ||
      hotfix_is_vulnerable (os:"5.0", file:"msadco.dll", version:"2.53.6306.0", path:path) )
 {
 set_kb_item(name:"SMB/Missing/MS06-014", value:TRUE);
 hotfix_security_warning();
 }
 
 hotfix_check_fversion_end(); 
}
