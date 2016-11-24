#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11413);
 script_version("$Revision: 1.25 $");

 script_cve_id("CVE-2003-0109");
 script_bugtraq_id(7116);
 script_xref(name:"IAVA", value:"2003-A-0005");
 script_xref(name:"OSVDB", value:"4467");

 script_name(english:"MS03-007: Unchecked Buffer in ntdll.dll (815021)");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a buffer overflow in the Windows
kernel which may allow an attacker to execute arbitrary code on the remote
host with the SYSTEM privileges.

For example this vulnerability can be exploited through the WebDAV component
of IIS 5.0.

A public code is available to exploit this flaw." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows NT, 2000 and XP :

http://www.microsoft.com/technet/security/bulletin/ms03-007.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Checks for MS Hotfix Q815021");
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

if ( hotfix_check_sp(nt:7, xp:2, win2k:4) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", sp:1, file:"Ntdll.dll", version:"5.1.2600.1217", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"Ntdll.dll", version:"5.1.2600.114", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Ntdll.dll", version:"5.0.2195.6685", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"Ntdll.dll", version:"4.0.1381.7212", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"Ntdll.dll", version:"4.0.1381.33546", min_version:"4.0.1381.33000", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS03-007", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"Q811493") > 0 &&
          hotfix_missing(name:"Q815021") > 0 &&
          hotfix_missing(name:"840987") > 0 )
{
 if ( hotfix_check_sp(xp:2) > 0 && hotfix_missing(name:"890859") <= 0 ) exit(0);
	 {
 set_kb_item(name:"SMB/Missing/MS03-007", value:TRUE);
 hotfix_security_hole();
 }
}
