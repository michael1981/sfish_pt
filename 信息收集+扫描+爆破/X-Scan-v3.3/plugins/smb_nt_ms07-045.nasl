#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(25883);
 script_version("$Revision: 1.13 $");

 script_cve_id(
  "CVE-2007-0319",
  "CVE-2007-0943",
  "CVE-2007-2216",
  "CVE-2007-2240",
  "CVE-2007-2928",
  "CVE-2007-2929",
  "CVE-2007-3041"
 );
 script_bugtraq_id(25288, 25289, 25295, 25311, 25312);
 script_xref(name:"OSVDB", value:"36395");
 script_xref(name:"OSVDB", value:"36396");
 script_xref(name:"OSVDB", value:"36397");
 script_xref(name:"OSVDB", value:"37710");
 script_xref(name:"OSVDB", value:"39553");
 script_xref(name:"OSVDB", value:"39554");
 script_xref(name:"OSVDB", value:"39555");

 name["english"] = "MS07-045: Cumulative Security Update for Internet Explorer (937143)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web
client." );
 script_set_attribute(attribute:"description", value:
"The remote host is missing IE Cumulative Security Update 937143. 

The remote version of IE is potentially vulnerable to several flaws
that may allow an attacker to execute arbitrary code on the remote
host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003 and
Vista :

http://www.microsoft.com/technet/security/Bulletin/MS07-045.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Determines the presence of update 937143";

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
 if ( hotfix_is_vulnerable (os:"6.0", sp:0, file:"Mshtml.dll", version:"7.0.6000.20643", min_version:"7.0.6000.20000", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"Mshtml.dll", version:"7.0.6000.16527", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Mshtml.dll", version:"6.0.3790.2954", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:2, file:"Mshtml.dll", version:"6.0.3790.4106", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", file:"Mshtml.dll", version:"7.0.6000.16525", min_version:"7.0.0.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", file:"Mshtml.dll", version:"7.0.6000.20641", min_version:"7.0.6000.20000", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Mshtml.dll", version:"6.0.2900.3157", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Mshtml.dll", version:"7.0.6000.16525", min_version:"7.0.0.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Mshtml.dll", version:"6.0.2800.1597", min_version:"6.0.0.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Mshtml.dll", version:"5.0.3854.1200", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS07-045", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
