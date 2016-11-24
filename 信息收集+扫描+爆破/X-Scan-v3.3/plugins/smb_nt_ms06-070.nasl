#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(23646);
 script_version("$Revision: 1.7 $");

 script_cve_id("CVE-2006-4691");
 script_bugtraq_id(20985);
 script_xref(name:"OSVDB", value:"30263");

 name["english"] = "MS06-070: Vulnerability in Workstation Service Could Allow Remote Code Execution (924270)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host due to a flaw in the 
'workstation' service." );
 script_set_attribute(attribute:"description", value:
"The remote host is vulnerable to a buffer overrun in the 'workstation' service
which may allow an attacker to execute arbitrary code on the remote host
with the 'System' privileges." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000 and XP :

http://www.microsoft.com/technet/security/bulletin/ms06-070.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 
 summary["english"] = "Determines the presence of update 924270";

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


if ( hotfix_check_sp(xp:3, win2k:6) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", sp:2, file:"Netapi32.dll", version:"5.1.2600.2976", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Netapi32.dll", version:"5.0.2195.7108", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS06-070", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"924270") > 0 )
	 {
 set_kb_item(name:"SMB/Missing/MS06-070", value:TRUE);
 hotfix_security_hole();
 }
