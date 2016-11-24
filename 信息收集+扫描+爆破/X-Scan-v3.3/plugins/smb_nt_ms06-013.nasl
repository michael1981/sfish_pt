#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(21210);
 script_version("$Revision: 1.20 $");

 script_cve_id(
  "CVE-2006-1359", 
  "CVE-2006-1245", 
  "CVE-2006-1388", 
  "CVE-2006-1185", 
  "CVE-2006-1186", 
  "CVE-2006-1188", 
  "CVE-2006-1189", 
  "CVE-2006-1190", 
  "CVE-2006-1191", 
  "CVE-2006-1192"
 );
 script_bugtraq_id(
  17131, 
  17181, 
  17196, 
  17468, 
  17460, 
  17457, 
  17455, 
  17454, 
  17453, 
  17450
 );
 script_xref(name:"OSVDB", value:"23964");
 script_xref(name:"OSVDB", value:"24050");
 script_xref(name:"OSVDB", value:"24095");
 script_xref(name:"OSVDB", value:"24541");
 script_xref(name:"OSVDB", value:"24542");
 script_xref(name:"OSVDB", value:"24543");
 script_xref(name:"OSVDB", value:"24544");
 script_xref(name:"OSVDB", value:"24545");
 script_xref(name:"OSVDB", value:"24546");
 script_xref(name:"OSVDB", value:"24547");

 name["english"] = "MS06-013: Cumulative Security Update for Internet Explorer (912812)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web
client." );
 script_set_attribute(attribute:"description", value:
"The remote host is missing IE Cumulative Security Update 912812. 

The remote version of IE is vulnerable to several flaws that may allow
an attacker to execute arbitrary code on the remote host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 
2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-013.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Determines the presence of update 912812";
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
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Mshtml.dll", version:"6.0.3790.497", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Mshtml.dll", version:"6.0.3790.2666", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Mshtml.dll", version:"6.0.2800.1543", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Mshtml.dll", version:"6.0.2900.2873", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Mshtml.dll", version:"6.0.2800.1543", min_version:"6.0.0.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Mshtml.dll", version:"5.0.3839.2200", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS06-013", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
