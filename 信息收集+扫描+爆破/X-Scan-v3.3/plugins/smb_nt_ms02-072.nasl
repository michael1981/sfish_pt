#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11194);
 script_version("$Revision: 1.15 $");

 script_cve_id("CVE-2002-1327");
 script_bugtraq_id(6427);
 script_xref(name:"OSVDB", value:"13413");

 name["english"] = "MS02-072: Unchecked Buffer in XP Shell Could Enable System Compromise (329390)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Windows
Shell." );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a flaw in the handling of audio
files (MP3, WMA) in the Windows Shell component, which may allow an
attacker to execute arbitrary code on the remote host with SYSTEM
privileges." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP :

http://www.microsoft.com/technet/security/bulletin/ms02-072.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Checks for MS Hotfix 329390, Flaw in Microsoft XP Shell";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
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

if ( hotfix_check_sp(xp:2) <= 0 ) exit(0);


if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", sp:1, file:"Shmedia.dll", version:"6.0.2800.1125", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"Shmedia.dll", version:"6.0.2800.101", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS02-072", value:TRUE);
 security_hole(get_kb_item("SMB/transport"));
 }
 
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"Q329390") > 0 )
	 {
 set_kb_item(name:"SMB/Missing/MS02-072", value:TRUE);
 hotfix_security_hole();
 }
