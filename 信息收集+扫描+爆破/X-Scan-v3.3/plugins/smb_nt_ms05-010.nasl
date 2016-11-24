#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(16325);
 script_version("$Revision: 1.12 $");

 script_cve_id("CVE-2005-0050");
 script_bugtraq_id(12481);
 script_xref(name:"IAVA", value:"2005-t-0003");
 script_xref(name:"OSVDB", value:"13599");

 name["english"] = "MS05-010: Vulnerability in the License Logging Service (885834)";
 script_name(english:name["english"]);
 
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
"Microsoft has released a set of patches for Windows NT, 2000 and 
2003 :

http://www.microsoft.com/technet/security/bulletin/ms05-010.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Determines if hotfix 885834 has been installed";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");

if ( hotfix_check_sp(nt:7, win2k:5, win2003:1) <= 0 ) exit(0);
if ( hotfix_check_nt_server() <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Llssrv.exe", version:"5.2.3790.248", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Llssrv.exe", version:"5.0.2195.7021", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"Llssrv.exe", version:"4.0.1381.7345", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS05-010", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else
{
 if ( hotfix_missing(name:"885834") > 0  )
 {
 set_kb_item(name:"SMB/Missing/MS05-010", value:TRUE);
 hotfix_security_hole();
 }
}
