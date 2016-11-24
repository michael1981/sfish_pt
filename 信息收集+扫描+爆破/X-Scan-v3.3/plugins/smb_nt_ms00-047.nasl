#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if(description)
{
 script_id(10482);
 script_bugtraq_id(1514, 1515);
 script_xref(name:"OSVDB", value:"381");
 script_version ("$Revision: 1.28 $");
 script_cve_id("CVE-2000-0673");
 name["english"] = "MS00-047: NetBIOS Name Server Protocol Spoofing patch (269239)";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to spoof the netbios name." );
 script_set_attribute(attribute:"description", value:
"The hotfix for the 'NetBIOS Name Server Protocol Spoofing'
problem has not been applied.

This vulnerability allows a malicious user to make this
host think that its name has already been taken on the
network, thus preventing it to function properly as
a SMB server (or client)." );
 script_set_attribute(attribute:"solution", value:
"http://www.microsoft.com/technet/security/bulletin/ms00-047.mspx" );
 script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/support/kb/articles/q299/4/44.asp" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );


script_end_attributes();

 
 summary["english"] = "Determines whether the hotfix Q269239 is installed";
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

if  ( hotfix_check_sp(nt:7, win2k:2) <= 0 ) exit(0);
if  ( hotfix_missing(name:"Q299444") > 0 &&
      hotfix_missing(name:"Q269239") > 0 ) 
	{
	 {
 set_kb_item(name:"SMB/Missing/MS00-047", value:TRUE);
 hotfix_security_warning();
 }
	}

