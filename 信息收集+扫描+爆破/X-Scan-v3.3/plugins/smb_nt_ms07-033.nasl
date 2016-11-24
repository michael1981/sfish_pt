#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(25486);
 script_version("$Revision: 1.11 $");

 script_cve_id(
  "CVE-2007-0218", 
  "CVE-2007-1499", 
  "CVE-2007-1750", 
  "CVE-2007-3027", 
  "CVE-2007-1751", 
  "CVE-2007-2222"
 );
 script_bugtraq_id(22966, 24372, 24418, 24423, 24426, 24429);
 script_xref(name:"OSVDB", value:"34077");
 script_xref(name:"OSVDB", value:"35348");
 script_xref(name:"OSVDB", value:"35349");
 script_xref(name:"OSVDB", value:"35350");
 script_xref(name:"OSVDB", value:"35351");
 script_xref(name:"OSVDB", value:"35352");
 script_xref(name:"OSVDB", value:"35353");

 name["english"] = "MS07-033: Cumulative Security Update for Internet Explorer (933566)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web
client." );
 script_set_attribute(attribute:"description", value:
"The remote host is missing IE Cumulative Security Update 933566. 

The remote version of IE is affected by several flaws that may allow
an attacker to execute arbitrary code on the remote host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003 and
Vista :

http://www.microsoft.com/technet/security/Bulletin/MS07-033.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Determines the presence of update 933566";

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


if ( hotfix_check_sp(xp:3, win2003:3, win2k:6, vista:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"6.0", sp:0, file:"Mshtml.dll", version:"7.0.6000.20591", min_version:"7.0.6000.20000", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"Mshtml.dll", version:"7.0.6000.16481", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Mshtml.dll", version:"6.0.3790.2920", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:2, file:"Mshtml.dll", version:"6.0.3790.4064", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", file:"Mshtml.dll", version:"7.0.6000.16481", min_version:"7.0.0.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Mshtml.dll", version:"6.0.2900.3132", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Mshtml.dll", version:"7.0.6000.16481", min_version:"7.0.0.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Mshtml.dll", version:"6.0.2800.1595", min_version:"6.0.0.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Mshtml.dll", version:"5.0.3853.3000", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS07-033", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
