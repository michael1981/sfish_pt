#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(42438);
 script_version("$Revision: 1.2 $");

 script_cve_id("CVE-2009-2523");
 script_bugtraq_id(36921);
 script_xref(name:"OSVDB", value:"59855");

 script_name(english:"MS09-064: Vulnerability in the License Logging Service (974783)");
 script_summary(english:"Determines if hotfix 974783 has been installed");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a flaw in the Logging Service
that may allow an attacker to execute arbitrary code on the remote
host. 

To exploit this flaw, an attacker would need to send a malformed
packet to the remote logging service, and would be able to either
execute arbitrary code on the remote host or to perform a denial of
service." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000 :

http://www.microsoft.com/technet/security/bulletin/ms09-064.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
 script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/10" );
 script_set_attribute(attribute:"patch_publication_date", value:"2009/11/10" );
 script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/10" );
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");

if ( hotfix_check_sp(win2k:6) <= 0 ) exit(0, "The host is not affected based on its version / service pack.");
if ( hotfix_check_nt_server() <= 0 ) exit(0, "The host is not affected because it is not running the WinNT service.");

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.0", file:"Llssrv.exe", version:"5.0.2195.7337", dir:"\system32") )
 {
  set_kb_item(name:"SMB/Missing/MS09-064", value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end(); 
  exit(0, "Host is vulnerable");
 }
 else
 {
  hotfix_check_fversion_end(); 
  exit (0, "Host is patched.");
 }
}
else exit(1, "Could not connect to ADMIN$");
