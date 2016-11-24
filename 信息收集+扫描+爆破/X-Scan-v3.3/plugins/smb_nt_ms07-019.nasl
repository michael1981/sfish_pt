#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(25022);
 script_version("$Revision: 1.9 $");

 script_cve_id("CVE-2007-1204");
 script_bugtraq_id(23371);
 script_xref(name:"OSVDB", value:"34010");

 name["english"] = "MS07-019: Vulnerability in Universal Plug and Play Could Allow Remote Code Execution (931261)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host due to a flaw in the 
Plug-And-Play service." );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a flaw in the http request 
handler the Plug and Play service which may allow an attacker to 
execute arbitrary code on the remote host with the service privileges." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP :

http://www.microsoft.com/technet/security/bulletin/ms07-019.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:A/AC:H/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 
 summary["english"] = "Determines the presence of update 931261";

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
 
if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", sp:2, file:"Upnphost.dll", version:"5.1.2600.3077", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS07-019", value:TRUE);
 hotfix_security_warning();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"931261") > 0 ) 
 {
 set_kb_item(name:"SMB/Missing/MS07-019", value:TRUE);
 hotfix_security_warning();
 }
