#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(26961);

 script_cve_id("CVE-2007-2217");
 script_bugtraq_id(25909);
 script_xref(name:"OSVDB", value:"37627");
 
 script_version("$Revision: 1.8 $");

 name["english"] = "MS07-055: Vulnerability in Kodak Image Viewer Could Allow Remote Code Execution (923810)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Kodak Image
Viewer." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of the Kodak Image Viewer that
may allow arbitrary code to be run. 

An attacker may use this to execute arbitrary code on this host. 

To succeed, the attacker would have to send a rogue file to a user of
the remote computer and have it open it with this application." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 2003
:

http://www.microsoft.com/technet/security/bulletin/ms07-055.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 summary["english"] = "Determines the version of Kodak Image Viewer";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");

 script_require_ports(139, 445);
 exit(0);
}



include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


if ( hotfix_check_sp(xp:3, win2003:3, win2k:6) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:1, file:"tifflt.dll", version:"5.0.3900.7138", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:2, file:"tifflt.dll", version:"5.0.3900.7139", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"tifflt.dll", version:"5.0.3900.7136", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0",       file:"tifflt.dll", version:"5.0.3900.7134", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS07-055", value:TRUE);
 hotfix_security_hole();
 }
      hotfix_check_fversion_end(); 
}
