#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(22184);
 script_version("$Revision: 1.27 $");

 script_cve_id(
  "CVE-2004-1166",
  "CVE-2006-3280",
  "CVE-2006-3450",
  "CVE-2006-3451",
  "CVE-2006-3637",
  "CVE-2006-3638",
  "CVE-2006-3639",
  "CVE-2006-3640",
  "CVE-2006-3873",
  "CVE-2006-7066"
 );
 script_bugtraq_id(
  11826, 
  18277, 
  18682, 
  19228, 
  19312, 
  19316, 
  19339, 
  19340, 
  19400, 
  19987
 );
 script_xref(name:"OSVDB", value:"12299");
 script_xref(name:"OSVDB", value:"26956");
 script_xref(name:"OSVDB", value:"27533");
 script_xref(name:"OSVDB", value:"27850");
 script_xref(name:"OSVDB", value:"27851");
 script_xref(name:"OSVDB", value:"27852");
 script_xref(name:"OSVDB", value:"27853");
 script_xref(name:"OSVDB", value:"27854");
 script_xref(name:"OSVDB", value:"27855");
 script_xref(name:"OSVDB", value:"30834");

 name["english"] = "MS06-042: Cumulative Security Update for Internet Explorer (918899)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web
client." );
 script_set_attribute(attribute:"description", value:
"The remote host is missing IE Cumulative Security Update 918899.

The remote version of IE is vulnerable to several flaws that may allow
an attacker to execute arbitrary code on the remote host. 

Note that Microsoft has re-released this hotfix since the initial
version contained a buffer overflow." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 
2003 :

http://www.microsoft.com/technet/security/Bulletin/MS06-042.mspx" );
 script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/kb/923762/" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
 summary["english"] = "Determines the presence of update 918899";
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
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Urlmon.dll", version:"6.0.3790.566", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Mshtml.dll", version:"6.0.3790.2759", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Urlmon.dll", version:"6.0.2800.1572", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Mshtml.dll", version:"6.0.2900.2963", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Urlmon.dll", version:"6.0.2800.1572", min_version:"6.0.0.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Urlmon.dll", version:"5.0.3844.3000", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS06-042", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
