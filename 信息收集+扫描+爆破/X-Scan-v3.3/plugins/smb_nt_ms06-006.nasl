#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(20906);
 script_version("$Revision: 1.10 $");

 script_cve_id("CVE-2006-0005");
 script_bugtraq_id(16644);
 script_xref(name:"OSVDB", value:"23132");
 
 name["english"] = "MS06-006: Vulnerability in Windows Media Player Plug-in Could Allow Remote Code Execution (911564)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Media
Player." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the Windows Media Player plug-in. 

There is a vulnerability in the remote version of this software that
may allow an attacker to execute arbitrary code on the remote host. 

To exploit this flaw, one attacker would need to send a specially
crafted media file with a rogue EMBED element and have a user on the
affected host open it with the plug-in." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 
2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-006.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Checks the version of Media Player";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
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

port = kb_smb_transport ();

if ( hotfix_check_sp(xp:3, win2k:6, win2003:2) <= 0 ) exit(0);


path = get_kb_item("SMB/WindowsMediaPlayer_path");
if(!path)exit(0);

if (is_accessible_share())
{
  if ( hotfix_check_fversion(path:path, file:"Npdsplay.dll", version:"3.0.2.629") == HCF_OLDER ) {
 set_kb_item(name:"SMB/Missing/MS06-006", value:TRUE);
 hotfix_security_hole();
 }

   hotfix_check_fversion_end(); 
}
