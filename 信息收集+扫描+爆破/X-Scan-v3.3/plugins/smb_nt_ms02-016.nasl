#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10945);
 script_version("$Revision: 1.19 $");

 script_cve_id("CVE-2002-0051");
 script_bugtraq_id(4438);
 script_xref(name:"OSVDB", value:"773");

 script_name(english:"MS02-016: Opening Group Policy Files (318089)");
 
 script_set_attribute(attribute:"synopsis", value:
"A user can block access to GPO deployment." );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a flaw in the Group Policy
Object (GPO) access right of Active Directory that may allow a user to
prevent the GPO to be applied to other users." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000 :

http://www.microsoft.com/technet/security/bulletin/ms02-016.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:S/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Determines whether the Group Policy patch (Q318593) is installed");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

#

include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

if ( hotfix_check_domain_controler() <= 0 ) exit(0);
if ( hotfix_check_sp(win2k:3) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q318593") > 0 ) 
	 {
 set_kb_item(name:"SMB/Missing/MS02-016", value:TRUE);
 hotfix_security_warning();
 }

