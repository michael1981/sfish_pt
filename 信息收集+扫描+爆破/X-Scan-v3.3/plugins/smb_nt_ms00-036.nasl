
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10434);
 script_bugtraq_id(1262);
 script_xref(name:"OSVDB", value:"336");
 script_version ("$Revision: 1.29 $");
 script_cve_id("CVE-2000-0404");
 name["english"] = "MS00-036: NT ResetBrowser frame & HostAnnouncement flood patch (262694)";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to partially crash the remote host." );
 script_set_attribute(attribute:"description", value:
"The hotfix for the 'ResetBrowser Frame' and the 'HostAnnouncement flood'
has not been applied.

The first of these vulnerabilities allows anyone to shut
down the network browser of this host at will.

The second vulnerability allows an attacker to
add thousands of bogus entries in the master browser,
which will consume most of the network bandwidth as
a side effect." );
 script_set_attribute(attribute:"solution", value:
"http://www.microsoft.com/technet/security/bulletin/ms00-036.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 
 summary["english"] = "Determines whether the hotfix Q262694 is installed";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


if ( hotfix_check_sp(nt:7, win2k:2) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q299444") > 0 &&
     hotfix_missing(name:"Q262694") > 0 )
		 {
 set_kb_item(name:"SMB/Missing/MS00-036", value:TRUE);
 hotfix_security_warning();
 }
