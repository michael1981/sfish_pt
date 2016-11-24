#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(25689);
 script_version("$Revision: 1.10 $");

 script_cve_id("CVE-2007-3038");
 script_bugtraq_id(24779);
 script_xref(name:"OSVDB", value:"35952");

 name["english"] = "MS07-038: Vulnerability in Windows Vista Firewall Could Allow Information Disclosure (935807)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows Vista system contains a firewall that is affected
by an information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows Vista contains a firewall that suffers
from an information disclosure vulnerability. 

By sending specially crafted packets, an attacker may be able to
access some ports of the remote host by going through its Teredo
interface." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista :

See: http://www.microsoft.com/technet/security/bulletin/ms07-038.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N" );
script_end_attributes();

 
 summary["english"] = "Determines the presence of update 935807";

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



include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");


if ( hotfix_check_sp(vista:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"6.0", sp:0, file:"tunnel.sys", version:"6.0.6000.16501", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"tunnel.sys", version:"6.0.6000.20614", min_version:"6.0.6000.20000", dir:"\system32\drivers") )
 {
 set_kb_item(name:"SMB/Missing/MS07-038", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
