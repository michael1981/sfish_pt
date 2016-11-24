#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10525);
 script_bugtraq_id(1743);
 script_xref(name:"OSVDB", value:"424");
 script_version ("$Revision: 1.26 $");
 name["english"] = "MS00-070: LPC and LPC Ports Vulnerabilities patch (266433)";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"A local user can elevate his privileges." );
 script_set_attribute(attribute:"description", value:
"The hotfix for the multiple LPC and LPC Ports vulnerabilities 
has not been applied on the remote Windows host.

These vulnerabilities allows an attacker gain privileges on the
remote host, or to crash it remotely." );
 script_set_attribute(attribute:"solution", value:
"http://www.microsoft.com/technet/security/bulletin/ms00-070.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 summary["english"] = "Determines whether the hotfix Q266433 is installed";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


if ( hotfix_check_sp(nt:7, win2k:2) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q299444") > 0 &&
     hotfix_missing(name:"Q266433") > 0 ) 
	 {
 set_kb_item(name:"SMB/Missing/MS00-070", value:TRUE);
 hotfix_security_hole();
 }
