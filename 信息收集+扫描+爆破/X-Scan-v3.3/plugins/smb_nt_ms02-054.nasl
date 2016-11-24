#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11148);
 script_version("$Revision: 1.20 $");

 script_cve_id("CVE-2002-0370", "CVE-2002-1139"); 
 script_bugtraq_id(5873, 5876);
 script_xref(name:"OSVDB", value:"868");
 script_xref(name:"OSVDB", value:"59738");

 script_name(english:"MS02-054: Unchecked Buffer in File Decompression Functions Could Lead to Code Execution (329048)");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Explorer." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of Windows that has a security flaw
in the compressed files (ZIP) implementation.  An attacker can exploit
this flaw by sending a malicious zip file to the remote user.  When
the user opens the file with Explorer, arbitrary code will be
executed." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows NT, 2000 and XP :

http://www.microsoft.com/technet/security/bulletin/ms02-054.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Checks for MS Hotfix Q329048, Unchecked Buffer in Decompression functions");
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
 if ( hotfix_is_vulnerable (os:"5.1", sp:1, file:"Zipfldr.dll", version:"6.0.2800.1126", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"Zipfldr.dll", version:"6.0.2600.101", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS02-054", value:TRUE);
 security_hole(get_kb_item("SMB/transport"));
 }
 
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"329048") > 0 &&
          hotfix_missing(name:"873376") > 0 )
 {
 set_kb_item(name:"SMB/Missing/MS02-054", value:TRUE);
 hotfix_security_hole();
 }

