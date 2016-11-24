#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(34403);
 script_version("$Revision: 1.7 $");

 script_cve_id("CVE-2008-2947", "CVE-2008-3472", "CVE-2008-3473", "CVE-2008-3474", "CVE-2008-3475", "CVE-2008-3476");
 script_bugtraq_id(29960, 31615, 31616, 31617, 31618, 31654);
 script_xref(name:"OSVDB", value:"46630");
 script_xref(name:"OSVDB", value:"49113");
 script_xref(name:"OSVDB", value:"49114");
 script_xref(name:"OSVDB", value:"49115");
 script_xref(name:"OSVDB", value:"49116");
 script_xref(name:"OSVDB", value:"49117");
 script_xref(name:"OSVDB", value:"49118");

 name["english"] = "MS08-058: Microsoft Internet Explorer Multiple Vulnerabilities (956390)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web client." );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the IE cumulative security update 956390.

The remote version of IE is vulnerable to several flaws which may allow an 
attacker to execute arbitrary code on the remote host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003, Vista and 2008:

http://www.microsoft.com/technet/security/Bulletin/MS08-058.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 
 summary["english"] = "Determines the presence of update 956390";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
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


if ( hotfix_check_sp(xp:4, win2003:3, win2k:6, vista:2) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( 
      hotfix_is_vulnerable (os:"6.0", sp:1, file:"Mshtml.dll", version:"7.0.6001.22260", min_version:"7.0.6001.20000", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:1, file:"Mshtml.dll", version:"7.0.6001.18137", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"Mshtml.dll", version:"7.0.6000.22260", min_version:"7.0.6000.20000", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"Mshtml.dll", version:"7.0.6000.16746", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Mshtml.dll", version:"6.0.3790.3194", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:2, file:"Mshtml.dll", version:"6.0.3790.4357", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", file:"Mshtml.dll", version:"7.0.6000.20900", min_version:"7.0.6000.20000", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", file:"Mshtml.dll", version:"7.0.6000.16735", min_version:"7.0.0.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", file:"Mshtml.dll", version:"7.0.6000.20900", min_version:"7.0.6000.20000", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", file:"Mshtml.dll", version:"7.0.6000.16735", min_version:"7.0.0.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:3, file:"Mshtml.dll", version:"6.0.2900.5659", dir:"\system32", min_version:"6.0.2900.0") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Mshtml.dll", version:"6.0.2900.3429", dir:"\system32", min_version:"6.0.2900.0") ||
      hotfix_is_vulnerable (os:"5.1", file:"Mshtml.dll", version:"6.0.2800.1615", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Mshtml.dll", version:"6.0.2800.1615", min_version:"6.0.0.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Mshtml.dll", version:"5.0.3868.2000", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS08-058", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
