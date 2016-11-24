#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(35074);
 script_version("$Revision: 1.6 $");

 script_cve_id("CVE-2008-4268", "CVE-2008-4269");
 script_bugtraq_id(32651, 32652);
 script_xref(name:"OSVDB", value:"50565");
 script_xref(name:"OSVDB", value:"50566");

 script_name(english: "MS08-075: Vulnerabilities in Windows Search Could Allow Remote Code Execution (959349)");

 script_set_attribute(attribute:"synopsis", value:
"Vulnerabilities in the Windows Shell may allow an attacker to execute
privileged commands on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a version of the Windows Shell
which contains a vulnerability in the way it handles saved seaches..

An attacker might use this flaw to trick an administrator to execute a saved
search and therefore execute arbitrary commands on his behalf." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista and 2008 :

http://www.microsoft.com/technet/security/bulletin/ms08-075.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 
 summary["english"] = "Determines the presence of update 959349";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
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


if ( hotfix_check_sp(vista:2, win2008:2) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"6.0", sp:0, file:"Explorer.exe", version:"6.0.6000.16771") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"Explorer.exe", version:"6.0.6000.20947", min_version:"6.0.6000.20000") ||
      hotfix_is_vulnerable (os:"6.0", sp:1, file:"Explorer.exe", version:"6.0.6001.18164") ||
      hotfix_is_vulnerable (os:"6.0", sp:1, file:"Explorer.exe", version:"6.0.6001.22298", min_version:"6.0.6001.22000") )
 {
 set_kb_item(name:"SMB/Missing/MS08-075", value:TRUE);
 hotfix_security_warning();
 }
 hotfix_check_fversion_end(); 
}
