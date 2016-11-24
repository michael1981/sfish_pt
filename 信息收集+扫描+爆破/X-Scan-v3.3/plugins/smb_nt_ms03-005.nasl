#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11231);
 script_version("$Revision: 1.18 $");

 script_cve_id("CVE-2003-0004");
 script_bugtraq_id(6778);
 script_xref(name:"OSVDB", value:"13411");

 script_name(english:"MS03-005: Unchecked Buffer in XP Redirector (810577)");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a buffer overflow in the
Windows Redirector service that may allow an attacker to execute
arbitrary code on the remote host with SYSTEM privileges." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP :

http://www.microsoft.com/technet/security/bulletin/ms03-005.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Checks for MS Hotfix Q810577");
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

if ( hotfix_check_sp(xp:2) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", sp:1, file:"Mrxsmb.sys", version:"5.1.2600.1143", dir:"\system32\Drivers") ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"Mrxsmb.sys", version:"5.1.2600.106", dir:"\system32\Drivers") )
 {
 set_kb_item(name:"SMB/Missing/MS03-005", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"810577") > 0 &&
          hotfix_missing(name:"885835") > 0  )
	 {
 set_kb_item(name:"SMB/Missing/MS03-005", value:TRUE);
 hotfix_security_hole();
 }
