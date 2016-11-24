#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if(description)
{
 script_id(10486);
 script_bugtraq_id(1507);
 script_xref(name:"OSVDB", value:"385");
 script_version ("$Revision: 1.31 $");
 script_cve_id("CVE-2000-0663");
 name["english"] = "MS00-052: Relative Shell Path patch (269049)";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"A local user can elevate his privileges" );
 script_set_attribute(attribute:"description", value:
"The hotfix for the 'Relative Shell Path' vulnerability has
not been applied.

This vulnerability allows a malicious user who can write to
the remote system root to cause the code of his choice to be
executed by the users who will interactively log into this
host." );
 script_set_attribute(attribute:"solution", value:
"http://www.microsoft.com/technet/security/bulletin/ms00-052.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 summary["english"] = "Determines whether the hotfix Q269239 is installed";
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
     hotfix_missing(name:"Q269049") > 0 )
	{
	 {
 set_kb_item(name:"SMB/Missing/MS00-052", value:TRUE);
 hotfix_security_hole();
 }
	}
