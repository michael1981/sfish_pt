#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(24335);
 script_version("$Revision: 1.11 $");

 script_cve_id("CVE-2007-0026");
 script_bugtraq_id(22483);
 script_xref(name:"OSVDB", value:"31885");

 name["english"] = "MS07-011: Vulnerability in Microsoft OLE Dialog Could Allow Remote Code Execution (926436)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the OLE Dialog 
component provided with Microsoft Windows." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of Microsoft Windows which has a
vulnerability in the OLE Dialog component which could be abused by an 
attacker to execute arbitrary code on the remote host.

To exploit this vulnerability, an attacker would need to spend a specially
crafted RTF file to a user on the remote host and lure him into opening it." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/Bulletin/MS07-011.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 
 summary["english"] = "Determines the presence of update 926436";

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

include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");

if ( hotfix_check_sp(xp:3, win2003:2, win2k:6) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:1, file:"Oledlg.dll", version:"5.2.3790.2813", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:0, file:"Oledlg.dll", version:"5.2.3790.601", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Oledlg.dll", version:"5.1.2600.3016", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Oledlg.dll", version:"5.0.2195.7114", dir:"\system32") )
   	 {
 set_kb_item(name:"SMB/Missing/MS07-011", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end();
 exit (0);
}
