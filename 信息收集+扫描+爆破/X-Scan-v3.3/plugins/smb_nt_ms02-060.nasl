#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11286);
 script_version("$Revision: 1.15 $");

 script_cve_id("CVE-2002-0974");
 script_bugtraq_id(5478);
 script_xref(name:"OSVDB", value:"3001");
 
 script_name(english:"MS02-060: Flaw in WinXP Help center could enable file deletion (328940)");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary files can be deleted on the remote host through the web client." );
 script_set_attribute(attribute:"description", value:
"There is a security vulnerability in the remote Windows XP Help and Support
Center which can be exploited by an attacker to delete arbitrary file
on this host.

To do so, an attacker needs to create malicious web pages that must
be visited by the owner of the remote system." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP and 2000 :

http://www.microsoft.com/technet/security/bulletin/ms02-060.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Checks for MS Hotfix Q328940");
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


if ( hotfix_check_sp(xp:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", sp:0, file:"Helpctr.exe", version:"5.1.2600.101", dir:"\pchealth\helpctr\binaries") )
 {
 set_kb_item(name:"SMB/Missing/MS02-060", value:TRUE);
 security_warning(get_kb_item("SMB/transport"));
 }
 
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"Q328940") > 0 )
 {
 set_kb_item(name:"SMB/Missing/MS02-060", value:TRUE);
 hotfix_security_warning();
 }

