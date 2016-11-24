#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11423);
 script_version("$Revision: 1.24 $");

 script_cve_id("CVE-2003-0010");
 script_bugtraq_id(7146);
 script_xref(name:"OSVDB", value:"14475");

 script_name(english:"MS03-008: Flaw in Windows Script Engine (814078)");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web
client." );
 script_set_attribute(attribute:"description", value:
"The remote host is vulnerable to a flaw in the Windows Script Engine,
which provides Windows with the ability to execute script code. 

To exploit this flaw, an attacker would need to lure one user on this
host to visit a rogue website or to send him an HTML e-mail with a
malicious code in it." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows NT, 2000 and XP :

http://www.microsoft.com/technet/security/bulletin/ms03-008.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Checks for MS Hotfix Q814078");
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


if ( hotfix_check_sp(xp:2, win2k:4) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", file:"Jscript.dll", version:"5.6.0.8513", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Jscript.dll", version:"5.5.0.8513", min_version:"5.5.0.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Jscript.dll", version:"5.1.0.813", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS03-008", value:TRUE);
 security_hole(get_kb_item("SMB/transport"));
 }
 
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"814078") > 0 && 
          hotfix_missing(name:"917344") > 0 )
 {
 set_kb_item(name:"SMB/Missing/MS03-008", value:TRUE);
 hotfix_security_hole();
 }
