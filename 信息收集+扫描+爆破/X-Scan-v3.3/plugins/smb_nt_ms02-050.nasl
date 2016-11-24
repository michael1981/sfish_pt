#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11145);
 script_version("$Revision: 1.28 $");

 script_cve_id("CVE-2002-0862", "CVE-2002-1183");
 script_bugtraq_id(5410);
 script_xref(name:"IAVA", value:"2003-b-0008");
 script_xref(name:"OSVDB", value:"865");
 script_xref(name:"OSVDB", value:"1832");

 script_name(english:"MS02-050: Certificate Validation Flaw Could Enable Identity Spoofing (328145)");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to spoof user identities." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the CryptoAPI that may allow an
attacker to spoof the identity of another user with malformed SSL
certificates." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows NT, 2000 and XP :

http://www.microsoft.com/technet/security/bulletin/ms02-050.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Checks for MS Hotfix Q328145, Certificate Validation Flaw");
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

if ( hotfix_check_sp(nt:7, win2k:5, xp:2) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", file:"Crypt32.dll", version:"5.131.2600.1123", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", sp:4, file:"Cryptdlg.dll", version:"5.0.1558.6608", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", sp:3, file:"Cryptdlg.dll", version:"5.0.1558.6072", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"Crypt32.dll", version:"5.131.1878.12", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS02-050", value:TRUE);
 security_hole(get_kb_item("SMB/transport"));
 }
 
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"Q329115") > 0  )
	 {
 set_kb_item(name:"SMB/Missing/MS02-050", value:TRUE);
 hotfix_security_hole();
 }
 
