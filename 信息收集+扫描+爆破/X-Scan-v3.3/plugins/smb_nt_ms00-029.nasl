#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10433);
 script_bugtraq_id(1236);
 script_xref(name:"IAVA", value:"2000-t-0005");
 script_xref(name:"OSVDB", value:"335");
 script_version ("$Revision: 1.30 $");
 script_cve_id("CVE-2000-0305");
 name["english"] = "MS00-029: NT IP fragment reassembly patch not applied (jolt2)(259728)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to crash the remote host." );
 script_set_attribute(attribute:"description", value:
"The hotfix for the 'IP Fragment Reassembly' vulnerability has not been
applied on the remote Windows host. 

This vulnerability allows an attacker to send malformed packets which
will utiliize 100% of the computer CPU, making it nearly unusable for
the legitimate users." );
 script_set_attribute(attribute:"solution", value:
"http://www.microsoft.com/technet/security/bulletin/ms00-029.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C" );

script_end_attributes();

 
 summary["english"] = "Determines whether the hotfix Q259728 is installed";
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
     hotfix_missing(name:"Q259728") > 0 ) 
	{
	 {
 set_kb_item(name:"SMB/Missing/MS00-029", value:TRUE);
 hotfix_security_hole();
 }
	}

