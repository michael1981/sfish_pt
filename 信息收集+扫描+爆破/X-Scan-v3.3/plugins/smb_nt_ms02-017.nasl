#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10944);
 script_version("$Revision: 1.21 $");

 script_cve_id("CVE-2002-0151");
 script_bugtraq_id(4426);
 script_xref(name:"IAVA", value:"2002-t-0007");
 script_xref(name:"OSVDB", value:"772");

 script_name(english:"MS02-017: MUP overlong request kernel overflow Patch (311967)");
 
 script_set_attribute(attribute:"synopsis", value:
"A local user can elevate his privileges." );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a flaw in Multiple UNC Provider
(MUP) service that may allow a local user to execute arbitrary code on
the remote host with SYSTEM privileges." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows NT, 2000 and XP :

http://www.microsoft.com/technet/security/bulletin/ms02-017.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"checks for Multiple UNC Provider Patch (Q311967)");
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

if ( hotfix_check_sp(nt:7, win2k:3, xp:1) <= 0 ) exit(0); 

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", sp:0, file:"Mup.sys", version:"5.1.2600.19", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.0", file:"Mup.sys", version:"5.0.2195.5080", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"4.0", file:"Mup.sys", version:"4.0.1381.7125", dir:"\system32\drivers") )
 {
 set_kb_item(name:"SMB/Missing/MS02-017", value:TRUE);
 security_hole(get_kb_item("SMB/transport"));
 }
 
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"Q312895") > 0 &&
          hotfix_missing(name:"Q311967") > 0 ) 
	 {
 set_kb_item(name:"SMB/Missing/MS02-017", value:TRUE);
 hotfix_security_hole();
 }

