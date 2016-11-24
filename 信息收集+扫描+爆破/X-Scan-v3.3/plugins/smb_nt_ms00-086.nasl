#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10632);
 script_bugtraq_id(1912);
 script_xref(name:"OSVDB", value:"525");
 script_version ("$Revision: 1.26 $");
 script_cve_id("CVE-2000-0886");

 
 name["english"] = "MS00-086: Webserver file request parsing (277873)";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host." );
 script_set_attribute(attribute:"description", value:
"The hotfix for the 'Webserver file request parsing' problem
has not been applied.

This vulnerability can allow an attacker to make the remote
IIS server make execute arbitrary commands." );
 script_set_attribute(attribute:"solution", value:
"http://www.microsoft.com/technet/security/bulletin/ms00-086.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 
 summary["english"] = "Determines whether the hotfix Q277873 is installed";
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
if ( (hotfix_missing(name:"293826") <= 0) || 
     (hotfix_missing(name:"295534") <= 0) || 
     (hotfix_missing(name:"301625") <= 0) || 
     (hotfix_missing(name:"317636") <= 0) ||
     (hotfix_missing(name:"299444") <= 0) ||
     (hotfix_missing(name:"SP2SRP1") <= 0) ) exit(0);
if ( hotfix_missing(name:"Q277873") > 0 )
	 {
 set_kb_item(name:"SMB/Missing/MS00-086", value:TRUE);
 hotfix_security_hole();
 }

