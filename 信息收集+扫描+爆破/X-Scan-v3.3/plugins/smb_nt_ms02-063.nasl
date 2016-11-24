#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11178);
 script_version("$Revision: 1.21 $");

 script_cve_id("CVE-2002-1214");
 script_bugtraq_id(5807, 6067);
 script_xref(name:"OSVDB", value:"13422");

 script_name(english:"MS02-063: Unchecked Buffer in PPTP Implementation Could Enable DOS Attacks (329834)");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to crash the remote system." );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a flaw in its PPTP
implementation.  If the remote host is configured to act as a PPTP
server, a remote attacker can send a specially crafted packet to
corrupt the kernel memory and crash the remote system." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP and 2000 :

http://www.microsoft.com/technet/security/bulletin/ms02-063.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C" );

script_end_attributes();

 script_summary(english:"Checks for MS Hotfix Q329834, Unchecked Buffer in PPTP DOS");
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

if ( hotfix_check_sp(win2k:4, xp:2) <= 0 ) exit(0);


if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", sp:1, file:"Raspptp.sys", version:"5.1.2600.1129", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"Raspptp.sys", version:"5.1.2600.101", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.0", file:"Raspptp.sys", version:"5.0.2195.6076", dir:"\system32\drivers") )
 {
 set_kb_item(name:"SMB/Missing/MS02-063", value:TRUE);
 security_warning(get_kb_item("SMB/transport"));
 }
 
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"Q329834") > 0 )
 {
 set_kb_item(name:"SMB/Missing/MS02-063", value:TRUE);
 hotfix_security_warning();
 }
