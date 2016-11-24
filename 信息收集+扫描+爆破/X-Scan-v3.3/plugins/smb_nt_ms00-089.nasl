#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#



include("compat.inc");

if(description)
{
 script_id(10555);
 script_cve_id("CVE-2000-1217");
 script_bugtraq_id(1973);
 script_xref(name:"OSVDB", value:"454");
 script_version ("$Revision: 1.25 $");
 
 name["english"] = "MS00-089: Domain account lockout vulnerability (274372)";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"A security update is missing on the remote host." );
 script_set_attribute(attribute:"description", value:
"The hotfix for the 'domain account lockout' problem has
not been applied.

This vulnerability allows a user to bypass the domain 
account lockout policy, and hence attempt to brute force
a user account." );
 script_set_attribute(attribute:"solution", value:
"See http://www.microsoft.com/technet/security/bulletin/ms00-089.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 
 summary["english"] = "Determines whether the hotfix Q274372 is installed";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 - 2009 Renaud Deraison");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

if ( hotfix_check_sp(win2k:2) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q274372") > 0 ) 
	 {
 set_kb_item(name:"SMB/Missing/MS00-089", value:TRUE);
 hotfix_security_hole();
 }

