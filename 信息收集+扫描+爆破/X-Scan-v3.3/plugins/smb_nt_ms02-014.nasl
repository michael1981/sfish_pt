#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11307);
 script_version("$Revision: 1.16 $");
 
 script_cve_id("CVE-2002-0070");
 script_bugtraq_id(4248);
 script_xref(name:"OSVDB", value:"2051");
 
 script_name(english:"MS02-014: Unchecked buffer in Windows Shell (313829)");
 
 script_set_attribute(attribute:"synopsis", value:
"A local user can elevate his privileges." );
 script_set_attribute(attribute:"description", value:
"The Windows shell of the remote host has an unchecked buffer that can
be exploited by a local attacker to run arbitrary code on this host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows NT and 2000 :

http://www.microsoft.com/technet/security/bulletin/ms02-014.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Checks for MS Hotfix Q216840");
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

if ( hotfix_check_sp(nt:7, win2k:3) <= 0 ) exit(0);
if ( hotfix_check_sp(win2k:3) > 0 )
{
 if ( hotfix_missing(name:"839645") == 0 ) exit(0);
}

if ( hotfix_missing(name:"313829") > 0 && hotfix_missing(name:"841356") > 0 )
	 {
 set_kb_item(name:"SMB/Missing/MS02-014", value:TRUE);
 hotfix_security_hole();
 }

