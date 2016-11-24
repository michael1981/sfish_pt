#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(16331);
 script_version("$Revision: 1.14 $");

 script_cve_id("CVE-2005-0051");
 script_bugtraq_id(12486);
 script_xref(name:"OSVDB", value:"13596");

 name["english"] = "MS05-007: Vulnerability in Windows Could Allow Information Disclosure (888302)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to disclose information about the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a flaw that may allow an
attacker to cause it to disclose information over the use of a named
pipe through a NULL session. 

An attacker may exploit this flaw to gain more knowledge about the
remote host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a patch for Windows XP :

http://www.microsoft.com/technet/security/bulletin/MS05-007.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();

 
 summary["english"] = "Determines if hotfix 888302 has been installed";
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

if ( hotfix_check_sp(xp:3) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", sp:1, file:"Srvsvc.dll", version:"5.1.2600.1613", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Srvsvc.dll", version:"5.1.2600.2577", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS05-007", value:TRUE);
 hotfix_security_warning();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else
{
 if ( hotfix_missing(name:"888302") > 0  )
 {
 set_kb_item(name:"SMB/Missing/MS05-007", value:TRUE);
 hotfix_security_warning();
 }
}
