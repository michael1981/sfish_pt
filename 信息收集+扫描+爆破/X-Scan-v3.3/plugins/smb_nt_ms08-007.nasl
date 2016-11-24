#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(31041);
 script_version("$Revision: 1.8 $");

 script_cve_id("CVE-2008-0080");
 script_bugtraq_id(27670);
 script_xref(name:"OSVDB", value:"41460");

 name["english"] = "MS08-007: Vulnerability in WebDAV Mini-Redirector Could Allow Remote Code Execution (946026)";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to execute arbitrary code on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Windows which is vulnerable
to a flaw which may allow an attacker to execute arbitrary code on the remote
host.

Specifically, the remote version of Windows is vulnerable to a flaw in the
WebDav Mini-Redirector handler. By sending a specially malformed message,
an attacker may be able to take the complete control of the remote system." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP, 2003 and Vista :

http://www.microsoft.com/technet/security/bulletin/ms08-007.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 summary["english"] = "Determines if hotfix 946026 has been installed";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
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

if ( hotfix_check_sp(xp:3, win2003:3, vista:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"6.0", sp:0, file:"mrxdav.sys", version:"6.0.6000.20751", min_version:"6.0.6000.20000", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"mrxdav.sys", version:"6.0.6000.16626", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.2", sp:2, arch:"x86", file:"mrxdav.sys", version:"5.2.3790.4206", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, arch:"x86", file:"mrxdav.sys", version:"5.2.3790.3060", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, arch:"x64", file:"mrxdav.sys", version:"5.2.3790.3075", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.2", sp:2, arch:"x64", file:"mrxdav.sys", version:"5.2.3790.4221", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"mrxdav.sys", version:"5.1.2600.3276", dir:"\system32\drivers") )
 {
 set_kb_item(name:"SMB/Missing/MS08-007", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}

