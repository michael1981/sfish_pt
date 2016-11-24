#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(15460);
 script_version("$Revision: 1.13 $");

 script_cve_id("CVE-2004-0214", "CVE-2004-0572");
 script_bugtraq_id(10677);
 script_xref(name:"IAVA", value:"2004-A-0019");
 script_xref(name:"OSVDB", value:"10698");
 script_xref(name:"OSVDB", value:"10699");

 name["english"] = "MS04-037: Vulnerability in Windows Shell (841356)";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web client." );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a flaw in the Windows Shell which
may allow an attacker to execute arbitrary code on the remote host.

To exploit this flaw, an attacker would need to lure a victim into visiting
a malicious website or into opening a malicious file attachment." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows NT, 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms04-037.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 summary["english"] = "Determines if hotfix 841356 has been installed";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
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

if ( hotfix_check_sp(nt:7, win2k:5, xp:2, win2003:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Shell32.dll", version:"6.0.3790.205", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Shell32.dll", version:"6.0.2800.1580", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"Shell32.dll", version:"6.0.2750.166", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Shell32.dll", version:"5.0.3900.6975", dir:"\system32") || 
      hotfix_is_vulnerable (os:"4.0", file:"Shell32.dll", version:"4.72.3843.3100", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS04-037", value:TRUE);
 security_hole(get_kb_item("SMB/transport"));
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"841356") > 0  )
	 {
 set_kb_item(name:"SMB/Missing/MS04-037", value:TRUE);
 hotfix_security_hole();
 }

