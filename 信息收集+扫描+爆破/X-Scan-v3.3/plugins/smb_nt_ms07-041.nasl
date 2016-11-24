#
# (C) Tenable Network Security
#

include("compat.inc");

if(description)
{
 script_id(25692);
 script_version("$Revision: 1.10 $");
 script_cve_id("CVE-2005-4360");
 script_bugtraq_id(15921);
 script_xref(name:"OSVDB", value:"21805");

 name["english"] = "MS07-041: Vulnerability in Microsoft Internet Information Services Could Allow Remote Code Execution (939373)";

 script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote web server." );
 script_set_attribute(attribute:"description", value:
"The remote host has a version of IIS which is vulnerable to a remote
flaw which may allow an attacker to take the control of the remote web server
and execute arbitrary commands on the remote host with the SYSTEM privileges." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for IIS 5.1 on Windows XP :

http://www.microsoft.com/technet/security/bulletin/ms07-041.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C" );

script_end_attributes();

 
 summary["english"] = "Checks for ms07-041 over the registry";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
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

if ( hotfix_check_sp(xp:3) <= 0 ) exit(0);
if ( hotfix_check_iis_installed() <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", sp:2, file:"w3svc.dll", version:"5.1.2600.3163", dir:"\system32\inetsrv") )
 {
 set_kb_item(name:"SMB/Missing/MS07-041", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"939373") > 0 )	
	 {
 set_kb_item(name:"SMB/Missing/MS07-041", value:TRUE);
 hotfix_security_hole();
 }
