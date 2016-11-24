#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10964);
 script_version("$Revision: 1.21 $");

 script_cve_id("CVE-2002-0367");
 script_bugtraq_id(4287);
 script_xref(name:"OSVDB", value:"788");

 script_name(english:"MS02-024: Windows Debugger flaw can Lead to Elevated Privileges (320206)");
 
 script_set_attribute(attribute:"synopsis", value:
"A local user can elevate his privileges." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a flaw in the Windows Debugger that may allow
a local user to elevate his privileges. 

To exploit this vulnerability, a user needs to send a specially
crafted code to the Debbuging handler to execute arbitrary code with
SYSTEM privileges." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows NT and 2000 :

http://www.microsoft.com/technet/security/bulletin/ms02-024.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Checks for MS Hotfix Q320206, Elevated Privilege");
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

if ( hotfix_check_sp(nt:7, win2k:3) <= 0 ) exit(0);


if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.0", file:"Smss.exe", version:"5.0.2195.5695", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"Smss.exe", version:"4.0.1381.7152", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS02-024", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"Q320206") > 0 )
	 {
 set_kb_item(name:"SMB/Missing/MS02-024", value:TRUE);
 hotfix_security_hole();
 }

