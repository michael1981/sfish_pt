#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(16328);
 script_version("$Revision: 1.18 $");

 script_cve_id("CVE-2004-1244", "CVE-2004-0597");
 script_bugtraq_id(12485, 12506);
 script_xref(name:"IAVA", value:"2005-B-0006");
 script_xref(name:"OSVDB", value:"13597");
 script_xref(name:"OSVDB", value:"8312");
 script_xref(name:"OSVDB", value:"8326");

 name["english"] = "MS05-009: Vulnerability in PNG Processing Could Allow Remote Code Execution (890261)";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the Media
Player." );
 script_set_attribute(attribute:"description", value:
"The remote host is running either Windows Media Player 9 or MSN
Messenger. 

There is a vulnerability in the remote version of this software that
may allow an attacker to execute arbitrary code on the remote host. 

To exploit this flaw, one attacker would need to set up a rogue PNG
image and send it to a victim on the remote host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 
2003 :

http://www.microsoft.com/technet/security/bulletin/ms05-009.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Checks the version of Media Player";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_full_access","SMB/WindowsVersion");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");

port = get_kb_item("SMB/transport");
if(!port) port = 139;

patched = 0;

# Check Windows Media Player 9
if ( hotfix_check_sp(xp:3, win2k:5, win2003:1) <= 0 ) exit(0);

version = get_kb_item("SMB/WindowsMediaPlayer");
if(!version)exit(0);


if (is_accessible_share())
 {
   rootfile = hotfix_get_programfilesdir();

   if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Wmp.dll", version:"9.0.0.3250", min_version:"9.0.0.0", dir:"\system32") ||
       hotfix_is_vulnerable (os:"5.2", file:"Msmsgs.exe", version:"5.1.0.639", min_version:"5.1.0.0", path:rootfile, dir:"\Messenger") ||
       hotfix_is_vulnerable (os:"5.1", sp:1, file:"Wmp.dll", version:"9.0.0.3250", min_version:"9.0.0.0", dir:"\system32") ||
       hotfix_is_vulnerable (os:"5.1", sp:1, file:"Msmsgs.exe", version:"4.7.0.2010", min_version:"4.7.0.0", path:rootfile, dir:"\Messenger") ||
       hotfix_is_vulnerable (os:"5.1", sp:2, file:"Msmsgs.exe", version:"4.7.0.3001", min_version:"4.7.0.3000", path:rootfile, dir:"\Messenger") ||
       hotfix_is_vulnerable (os:"5.1", file:"Msmsgs.exe", version:"5.1.0.639", min_version:"5.1.0.0", path:rootfile, dir:"\Messenger") ||
       hotfix_is_vulnerable (os:"5.0", file:"Msmsgs.exe", version:"5.1.0.639", min_version:"5.1.0.0", path:rootfile, dir:"\Messenger") ||
       hotfix_is_vulnerable (os:"5.0", file:"Wmp.dll", version:"9.0.0.3250", min_version:"9.0.0.0", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS05-009", value:TRUE);
 security_hole(get_kb_item("SMB/transport"));
 }
  else
    patched ++; 
   hotfix_check_fversion_end(); 
 }

if ( patched )
	set_kb_item(name:"SMB/890261", value:TRUE);


