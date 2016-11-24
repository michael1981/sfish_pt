#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11300);
 script_version("$Revision: 1.19 $");

 script_cve_id("CVE-2002-0724");
 script_bugtraq_id(5556);
 script_xref(name:"OSVDB", value:"2074");
 
 script_name(english:"MS02-045: Unchecked buffer in Network Share Provider (326830)");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to crash the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is vulnerable to a denial of service attack, which
could allow an attacker to crash it by sending a specially-crafted
SMB (Server Message Block) request to it." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows NT, 2000 and XP :

http://www.microsoft.com/technet/security/bulletin/ms02-045.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C" );

script_end_attributes();

 script_summary(english:"Checks for MS Hotfix Q326830");
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

if ( hotfix_check_sp(nt:7, win2k:4, xp:1) <= 0 ) exit(0);


if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", sp:0, file:"Xactsrv.dll", version:"5.1.2600.50", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Xactsrv.dll", version:"5.0.2195.5971", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"Xactsrv.dll", version:"4.0.1381.7181", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"Xactsrv.dll", version:"4.0.1381.33538", min_version:"4.0.1381.33000", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS02-045", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"Q326830") > 0 )  
	 {
 set_kb_item(name:"SMB/Missing/MS02-045", value:TRUE);
 hotfix_security_hole();
 }

