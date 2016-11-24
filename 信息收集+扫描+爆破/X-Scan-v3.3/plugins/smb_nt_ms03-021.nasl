#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11774);
 script_version("$Revision: 1.23 $");

 script_cve_id("CVE-2003-0348");
 script_bugtraq_id(8034);
 script_xref(name:"OSVDB", value:"10997");
 
 name["english"] = "MS03-021: Windows Media Player Library Access (819639)";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the media player." );
 script_set_attribute(attribute:"description", value:
"An ActiveX control included with Windows Media Player 9 Series
may allow a rogue web site to gain information about the 
remote host.

An attacker may exploit this flaw to execute arbitrary code on this
host with the privileges of the user running Windows Media Player.

To exploit this flaw, an attacker would need to set up a rogue
web site and lure a user of this host into visiting it." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for WMP 6.4, 7.1 and XP :

http://www.microsoft.com/technet/security/bulletin/ms03-021.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 summary["english"] = "Checks the version of Media Player";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_nt_ms05-009.nasl", "smb_hotfixes.nasl");
 script_require_keys( "SMB/WindowsVersion", "SMB/registry_access");
 script_exclude_keys("SMB/Win2003/ServicePack");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

if ( get_kb_item("SMB/890261") ) exit(0);
if ( hotfix_missing(name:"911565") <= 0 )
  exit (0);

if ( hotfix_check_sp(win2k:5, xp:1, win2003:1) <= 0 ) exit(0);

port = get_kb_item("SMB/transport");
if(!port)port = 139;

access = get_kb_item("SMB/registry_full_access");
if(!access)exit(0);

version = get_kb_item("SMB/WindowsMediaPlayer");
if(!version)exit(0);

if (!ereg(pattern:"^9\,[0-9]\,[0-9]\,[0-9]", string:version))exit(0);

version = get_kb_item("SMB/WindowsVersion");

if (is_accessible_share())
{
 path = hotfix_get_systemroot() + "\system32";

 if ( hotfix_check_fversion(path:path, file:"Wmp.dll", version:"9.0.0.3008") == HCF_OLDER ) {
 set_kb_item(name:"SMB/Missing/MS03-021", value:TRUE);
 hotfix_security_warning();
 }

 hotfix_check_fversion_end();
 
 exit (0);
}

fix = get_kb_item ("SMB/Registry/HKLM/SOFTWARE/Microsoft/Updates/Windows Media Player/wm819639");
if(fix) exit(0);

fix = get_kb_item ("SMB/Registry/HKLM/SOFTWARE/Microsoft/Updates/Windows Media Player/wm828026");
if(fix) exit(0);

fix = get_kb_item ("SMB/Registry/HKLM/SOFTWARE/Microsoft/Updates/Windows Media Player/Q828026");
if(fix) exit(0);

 {
 set_kb_item(name:"SMB/Missing/MS03-021", value:TRUE);
 security_warning(port);
 }
