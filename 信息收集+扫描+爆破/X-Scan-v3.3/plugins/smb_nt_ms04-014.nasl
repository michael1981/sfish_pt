#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(12207);
 script_version("$Revision: 1.17 $");

 script_cve_id("CVE-2004-0197");
 script_bugtraq_id(10112);
 script_xref(name:"OSVDB", value:"5241");
 
 script_name(english:"MS04-014: Microsoft Hotfix (credentialed check) (837001)");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through database engine." );
 script_set_attribute(attribute:"description", value:
"The remote host has a bug in its Microsoft Jet Database Engine (837001).

An attacker may exploit one of these flaws to execute arbitrary code on the
remote system.

To exploit this flaw, an attacker would need the ability to craft a specially
malformed database query and have this engine execute it." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows NT, 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms04-014.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Checks for ms04-014");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
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

if ( hotfix_check_sp(nt:7, win2k:5, xp:2, win2003:1) <= 0 ) exit(0);


if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Msjet40.dll", version:"4.0.8618.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Msjet40.dll", version:"4.0.8618.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"Msjet40.dll", version:"4.0.8618.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Msjet40.dll", version:"4.0.8618.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"Msjet40.dll", version:"4.0.8618.0", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS04-014", value:TRUE);
 security_hole(get_kb_item("SMB/transport"));
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"KB837001") > 0 &&
          hotfix_missing(name:"KB950749") > 0 )
	 {
 set_kb_item(name:"SMB/Missing/MS04-014", value:TRUE);
 hotfix_security_hole();
 }

