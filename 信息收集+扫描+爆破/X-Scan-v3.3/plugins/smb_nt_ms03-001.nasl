#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(11212);
 script_version("$Revision: 1.20 $");

 script_cve_id("CVE-2003-0003");
 script_bugtraq_id(6666);
 script_xref(name:"IAVA", value:"2003-A-0007");
 script_xref(name:"OSVDB", value:"7117");

 name["english"] = "MS03-001: Unchecked buffer in Locate Service (810833)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host." );
 script_set_attribute(attribute:"description", value:
"The Microsoft Locate service is a name server that maps logical
names to network-specific names.

There is a security vulnerability in this server which allows
an attacker to execute arbitrary code in it by sending a specially
crafted packet to it." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows NT, 2000 and XP :

http://www.microsoft.com/technet/security/bulletin/ms03-001.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 summary["english"] = "Checks for MS Hotfix 810833";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl",
		     "smb_enum_services.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

if  ( hotfix_check_sp(nt:7, win2k:4, xp:2) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", sp:1, file:"Locator.exe", version:"5.1.2600.1147", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"Locator.exe", version:"5.1.2600.108", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Locator.exe", version:"5.0.2195.6136", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"Locator.exe", version:"4.0.1381.7202", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"Locator.exe", version:"4.0.1381.33534", min_version:"4.0.1381.33000", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS03-001", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end();
 exit (0);
}
else if  ( hotfix_missing(name:"Q810833") > 0 )
	{ 
	 {
 set_kb_item(name:"SMB/Missing/MS03-001", value:TRUE);
 hotfix_security_hole();
 }
	}
