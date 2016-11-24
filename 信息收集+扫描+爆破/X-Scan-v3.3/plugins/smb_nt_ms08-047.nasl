#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(33876);
 script_version("$Revision: 1.5 $");

 script_cve_id("CVE-2008-2246");
 script_bugtraq_id(30634);
 script_xref(name:"OSVDB", value:"47396");

 name["english"] = "MS08-047: Vulnerability in IPsec Policy Processing Could Allow Information Disclosure (953733)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host IPsec policy processing could lead to information
disclosure." );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a bug in its IPsec
implementation which might lead to information disclosure. 

Specifically, when importing a Windows Server 2003 IPsec policy into a
Windows Server 2008 domain, the system could ignore the IPsec policies
and transmit the traffic in clear text." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista and Server
2008 :

http://www.microsoft.com/technet/security/Bulletin/MS08-047.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:N/A:N" );


script_end_attributes();

 
 summary["english"] = "Determines the presence of update 953733";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}



include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


if ( hotfix_check_sp(vista:2) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( 
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"IPsecsvc.dll", version:"6.0.6000.16705", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"IPsecsvc.dll", version:"6.0.6000.20861", min_version:"6.0.6000.20000",  dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:1, file:"IPsecsvc.dll", version:"6.0.6001.22206", min_version:"6.0.6001.22000",  dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:1, file:"IPsecsvc.dll", version:"6.0.6001.18094",  dir:"\system32") )
			 {
 set_kb_item(name:"SMB/Missing/MS08-047", value:TRUE);
 hotfix_security_warning();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
