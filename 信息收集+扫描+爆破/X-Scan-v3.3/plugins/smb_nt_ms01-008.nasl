#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10693);
 script_version ("$Revision: 1.27 $");
 script_cve_id("CVE-2001-0016");
 script_bugtraq_id(2348);
 script_xref(name:"OSVDB", value:"572");
 
 script_name(english:"MS01-008: NTLMSSP Local Privilege Escalation (280119)");
 
 script_set_attribute(attribute:"synopsis", value:
"A bug in the remote operating system allows a local user to elevate his 
privileges." );
 script_set_attribute(attribute:"description", value:
"The hotfix for the 'NTLMSSP Privilege Escalation' problem has not been 
applied.  This hotfix corrects a problem in Windows NT which may allow a 
local process to execute code with the privileges of the NTLMSSP service
provider.

This vulnerability allows a malicious user, who has the right to log on this 
host locally, to gain additional privileges." );
 script_set_attribute(attribute:"solution", value:
"http://www.microsoft.com/technet/security/bulletin/ms01-008.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Determines whether the hotfix Q280119 is installed");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

#

include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

if ( hotfix_check_sp(nt:7) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q299444") > 0 && hotfix_missing(name:"Q280119") > 0 )
	 {
 set_kb_item(name:"SMB/Missing/MS01-008", value:TRUE);
 hotfix_security_hole();
 }

