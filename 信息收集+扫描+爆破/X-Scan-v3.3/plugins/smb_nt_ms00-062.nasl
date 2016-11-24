#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if(description)
{
 script_id(10499);
 script_bugtraq_id(1613);
 script_xref(name:"OSVDB", value:"398");
 script_version ("$Revision: 1.26 $");
 script_cve_id("CVE-2000-0771");

 name["english"] = "MS00-062: Local Security Policy Corruption (269609)";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"A local user can corrupt the remote system." );
 script_set_attribute(attribute:"description", value:
"The hotfix for the 'Local Security Policy Corruption'
problem has not been applied.

This vulnerability allows a malicious user to corrupt parts of
a Windows 2000 system's local security policy, which may
prevent this host from communicating with other hosts
in this domain." );
 script_set_attribute(attribute:"solution", value:
"http://www.microsoft.com/technet/security/bulletin/ms00-062.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 
 summary["english"] = "Determines whether the hotfix Q269609 is installed";
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

if ( hotfix_check_sp(win2k:1) <= 0 ) exit(0);

if ( hotfix_missing(name:"Q269609") > 0 ) 
	 {
 set_kb_item(name:"SMB/Missing/MS00-062", value:TRUE);
 hotfix_security_note();
 }
