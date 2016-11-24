#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11029);
 script_version("$Revision: 1.21 $");

 script_cve_id("CVE-2002-0366");
 script_bugtraq_id(4852);
 script_xref(name:"OSVDB", value:"837");

 script_name(english:"MS02-029: Windows RAS Local Overflow (318138)");
 
 script_set_attribute(attribute:"synopsis", value:
"A local user can elevate his privileges." );
 script_set_attribute(attribute:"description", value:
"An overflow in the RAS phonebook service allows a local user to
execute code on the system with the privileges of LocalSystem." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows NT, 2000 and XP :

http://www.microsoft.com/technet/security/bulletin/ms02-029.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Checks for MS Hotfix Q318138, Elevated Privilege");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

#

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

if ( hotfix_check_sp(nt:7, win2k:3, xp:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", sp:0, file:"Rasapi32.dll", version:"5.1.2600.28", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Rasapi32.dll", version:"5.0.2195.4983", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"Rasapi32.dll", version:"4.0.1381.7140", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS02-029", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"Q318138") > 0 ) 
	 {
 set_kb_item(name:"SMB/Missing/MS02-029", value:TRUE);
 hotfix_security_hole();
 }

