#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(23833);
 script_version("$Revision: 1.17 $");

 script_cve_id("CVE-2006-5579", "CVE-2006-5581", "CVE-2006-5578", "CVE-2006-5577");
 script_bugtraq_id(21552, 21507, 21546, 21494);
 script_xref(name:"OSVDB", value:"30813");
 script_xref(name:"OSVDB", value:"30814");
 script_xref(name:"OSVDB", value:"30815");
 script_xref(name:"OSVDB", value:"30816");

 name["english"] = "MS06-072: Cumulative Security Update for Internet Explorer (925454)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web client." );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the IE cumulative security update 925454.

The remote version of IE is vulnerable to several flaws which may allow an 
attacker to execute arbitrary code on the remote host.

Note that Microsoft has re-released this hotfix as its initial version
contained a buffer overflow." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/Bulletin/MS06-072.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 
 summary["english"] = "Determines the presence of update 925454";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
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


if ( hotfix_check_sp(xp:3, win2003:2, win2k:6) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Mshtml.dll", version:"6.0.3790.605", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Mshtml.dll", version:"6.0.3790.2817", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Mshtml.dll", version:"6.0.2900.3020", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Mshtml.dll", version:"6.0.2800.1586", min_version:"6.0.0.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Mshtml.dll", version:"5.0.3846.2300", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS06-072", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
