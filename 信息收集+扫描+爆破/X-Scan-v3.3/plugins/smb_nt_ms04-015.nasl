#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(12235);
 script_version("$Revision: 1.15 $");

 script_cve_id("CVE-2004-0199");
 script_bugtraq_id(10321);
 script_xref(name:"IAVA", value:"2004-t-0015");
 script_xref(name:"OSVDB", value:"6053");

 name["english"] = "MS04-015: Microsoft Help Center Remote Code Execution (840374)";
 script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web
client." );
 script_set_attribute(attribute:"description", value:
"The remote host contains bugs in the Microsoft Help and Support Center
in the way it handles HCP URL validation.  (840374)

An attacker could use this bug to execute arbitrary commands on the
remote host.  To exploit this bug, an attacker would need to lure a
user of the remote host into visiting a rogue website or to click on a
link received in an email." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2003 and XP :

http://www.microsoft.com/technet/security/bulletin/ms04-015.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Checks for ms04-015 over the registry";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
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

if ( hotfix_check_sp(xp:2, win2003:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Helpctr.exe", version:"5.2.3790.161", dir:"\pchealth\helpctr\binaries") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Helpctr.exe", version:"5.1.2600.1515", dir:"\pchealth\helpctr\binaries") ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"Helpctr.exe", version:"5.1.2600.137", dir:"\pchealth\helpctr\binaries") )
 {
 set_kb_item(name:"SMB/Missing/MS04-015", value:TRUE);
 security_hole(get_kb_item("SMB/transport"));
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"KB840374") > 0 )
	 {
 set_kb_item(name:"SMB/Missing/MS04-015", value:TRUE);
 hotfix_security_hole();
 }

