#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(13639);
 script_version("$Revision: 1.16 $");

 script_cve_id("CVE-2004-0205");
 script_bugtraq_id(10706);
 script_xref(name:"IAVA", value:"2004-B-0011");
 script_xref(name:"OSVDB", value:"7799");

 script_name(english:"MS04-021: IIS Redirection Vulnerability (credentialed check) (841373)");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote web server." );
 script_set_attribute(attribute:"description", value:
"The remote host has a version of IIS 4.0 that may allow an attacker to
take the control of the remote web server and execute arbitrary
commands on the remote host with the SYSTEM privileges." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for IIS 4.0 :

http://www.microsoft.com/technet/security/bulletin/ms04-021.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Checks for ms04-021 over the registry");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

#

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

if ( hotfix_check_sp(nt:7) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"4.0", file:"w3svc.dll", version:"4.2.788.1", dir:"\system32\inetsrv") )
 {
 set_kb_item(name:"SMB/Missing/MS04-021", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"KB841373") > 0 )	
	 {
 set_kb_item(name:"SMB/Missing/MS04-021", value:TRUE);
 hotfix_security_hole();
 }
