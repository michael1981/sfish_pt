#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(33443);
 script_version("$Revision: 1.7 $");

 script_cve_id("CVE-2008-2247", "CVE-2008-2248");
 script_bugtraq_id(30078, 30130);
 script_xref(name:"OSVDB", value:"46779");
 script_xref(name:"OSVDB", value:"46780");

 name["english"] = "MS08-039: Vulnerabilities in Outlook Web Access for Exchange Server Could Allow Elevation of Privilege (953747)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to cross-site scripting issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Outlook Web Access (OWA) for
Exchange Server which is vulnerable to multiple cross site scripting
issues in the HTML parser and Data validation code. 

These vulnerabilities may allow an attacker to elevate his privileges
by convincing a user to open a malformed email." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for OWA 2003 and 2007 :

http://www.microsoft.com/technet/security/bulletin/ms08-039.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );



script_end_attributes();

 
 summary["english"] = "Determines the version of Exchange";

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


version = get_kb_item ("SMB/Exchange/Version");
if ( !version ) exit (0);

path2003 = get_kb_item("SMB/Exchange/Path") + "\exchweb\bin\auth";
path2007 = hotfix_get_commonfilesdir() + "\Microsoft Shared\CDO";

if ( ( hotfix_check_fversion(path:path2003, file:"Owaauth.dll", version:"6.5.7653.38") == HCF_OLDER ) ||
     ( hotfix_check_fversion(path:path2007, file:"Cdoex.dll", version:"8.1.291.1", min_version:"8.1.0.0") == HCF_OLDER ) ||
     ( hotfix_check_fversion(path:path2007, file:"Cdoex.dll", version:"8.0.813.0", min_version:"8.0.0.0") == HCF_OLDER ) )
{
 {
 set_kb_item(name:"SMB/Missing/MS08-039", value:TRUE);
 hotfix_security_warning();
 }
 set_kb_item(name: 'www/0/XSS', value: TRUE);
}

hotfix_check_fversion_end();
