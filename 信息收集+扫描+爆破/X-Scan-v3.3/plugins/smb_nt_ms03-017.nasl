#
# (C) Tenable Network Security, Inc.
#
# Fixed in Windows XP SP1
#
# Vulnerable versions :
# 	Media Player in Windows XP preSP2
#	Media Player 7.1
#
#


include("compat.inc");

if(description)
{
 script_id(11595);
 script_version("$Revision: 1.21 $");

 script_cve_id("CVE-2003-0228");
 script_bugtraq_id(7517);
 script_xref(name:"OSVDB", value:"7738");
 
 name["english"] = "MS03-017: Windows Media Player Skin Download Overflow (817787)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the media
player." );
 script_set_attribute(attribute:"description", value:
"The remote host is using a version of Windows Media player that is
vulnerable to a directory traversal through its handling of 'skins'. 

An attacker may exploit this flaw to execute arbitrary code on this
host with the privileges of the user running Windows Media Player. 

To exploit this flaw, an attacker would need to craft a specially
malformed skin and send it to a user of this host, either directly
by e-mail or by sending a URL pointing to it.

Affected Software:

 - Microsoft Windows Media Player 7.1
 - Microsoft Windows Media Player for Windows XP (Version 8.0)" );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Media Player :

http://www.microsoft.com/technet/security/bulletin/ms03-017.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Checks the version of Media Player";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys( "SMB/WindowsVersion", "SMB/registry_access");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

if ( hotfix_check_sp(xp:2) <= 0 ) exit(0);

port = get_kb_item("SMB/transport");
if(!port)port = 139;

access = get_kb_item("SMB/registry_full_access");
if(!access)exit(0);

version = get_kb_item("SMB/WindowsMediaPlayer");
if(!version)exit(0);


if (is_accessible_share())
{
 path = hotfix_get_programfilesdir() + "\Windows Media Player";

 if ( hotfix_check_fversion(path:path, file:"Wmplayer.exe", version:"8.0.0.4490", min_version:"8.0.0.0") == HCF_OLDER ) {
 set_kb_item(name:"SMB/Missing/MS03-017", value:TRUE);
 hotfix_security_hole();
 }
 if ( hotfix_check_fversion(path:path, file:"Wmplayer.exe", version:"7.10.0.3074", min_version:"7.10.0.0") == HCF_OLDER ) {
 set_kb_item(name:"SMB/Missing/MS03-017", value:TRUE);
 hotfix_security_hole();
 }

 hotfix_check_fversion_end();
 
 exit (0);
}
else
{
 fix = get_kb_item ("SMB/Registry/HKLM/SOFTWARE/Microsoft/Updates/Windows Media Player/wm817787");
 if(!fix) {
 set_kb_item(name:"SMB/Missing/MS03-017", value:TRUE);
 hotfix_security_hole();
 }
}
