#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(22536);
 script_version("$Revision: 1.13 $");

 script_cve_id("CVE-2006-1314", "CVE-2006-1315", "CVE-2006-3942", "CVE-2006-4696");
 script_bugtraq_id(19215, 20373);
 script_xref(name:"OSVDB", value:"29439");
 script_xref(name:"OSVDB", value:"27644");
 script_xref(name:"OSVDB", value:"27155");
 script_xref(name:"OSVDB", value:"27154");

 script_name(english:"MS06-063: Vulnerability in Server Service Could Allow Denial of Service (923414)");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to crash the remote host due to a flaw in the 'server'
service." );
 script_set_attribute(attribute:"description", value:
"The remote host has a memory corruption vulnerability in the 'Server'
service that may allow an attacker to perform a denial of service
against the remote host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 
2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-063.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Determines the presence of update 923414");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

#

include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");


if ( hotfix_check_sp(xp:3, win2003:2, win2k:6) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Srv.sys", version:"5.2.3790.588", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Srv.sys", version:"5.2.3790.2783", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Srv.sys", version:"5.1.2600.1885", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Srv.sys", version:"5.1.2600.2974", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.0", file:"Srv.sys", version:"5.0.2195.7106", dir:"\system32\drivers") )
 {
 set_kb_item(name:"SMB/Missing/MS06-063", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}

