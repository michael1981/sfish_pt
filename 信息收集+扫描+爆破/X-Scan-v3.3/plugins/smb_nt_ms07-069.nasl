#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(29313);
 script_version("$Revision: 1.11 $");

 script_cve_id(
  "CVE-2007-0322",
  "CVE-2007-3902",
  "CVE-2007-3903",
  "CVE-2007-4471",
  "CVE-2007-5344",
  "CVE-2007-5347",
  "CVE-2007-6387"
 );
 script_bugtraq_id(25544, 26427, 26506, 26815, 26816, 26817, 26819);
 script_xref(name:"OSVDB", value:"37134");
 script_xref(name:"OSVDB", value:"37243");
 script_xref(name:"OSVDB", value:"39118");
 script_xref(name:"OSVDB", value:"39119");
 script_xref(name:"OSVDB", value:"39120");
 script_xref(name:"OSVDB", value:"39121");
 script_xref(name:"OSVDB", value:"42613");

 name["english"] = "MS07-069: Cumulative Security Update for Internet Explorer (942615)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web client." );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the IE cumulative security update 942615.

The remote version of IE is vulnerable to several flaws which may allow an 
attacker to execute arbitrary code on the remote host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003 and Vista :

http://www.microsoft.com/technet/security/Bulletin/MS07-069.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 
 summary["english"] = "Determines the presence of update 942615";

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
 if ( hotfix_is_vulnerable (os:"6.0", sp:0, file:"Mshtml.dll", version:"7.0.6000.20710", min_version:"7.0.6000.20000", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"Mshtml.dll", version:"7.0.6000.16587", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Mshtml.dll", version:"6.0.3790.3041", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:2, file:"Mshtml.dll", version:"6.0.3790.4186", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", file:"Mshtml.dll", version:"7.0.6000.20710", min_version:"7.0.6000.20000", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", file:"Mshtml.dll", version:"7.0.6000.16587", min_version:"7.0.0.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Mshtml.dll", version:"6.0.2900.3243", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Mshtml.dll", version:"7.0.6000.20710", min_version:"7.0.6000.20000", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Mshtml.dll", version:"7.0.6000.16587", min_version:"7.0.0.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Mshtml.dll", version:"6.0.2800.1605", min_version:"6.0.0.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Mshtml.dll", version:"5.0.3858.1100", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS07-069", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
