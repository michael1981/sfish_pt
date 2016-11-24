#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(21685);
 script_version("$Revision: 1.21 $");

 script_cve_id(
  "CVE-2006-1626", 
  "CVE-2006-1303", 
  "CVE-2006-2218", 
  "CVE-2006-2382", 
  "CVE-2006-2383", 
  "CVE-2006-2384", 
  "CVE-2006-2385"
 );
 script_bugtraq_id(17404, 17820, 18303, 18309, 18320, 18321, 18328);
 script_xref(name:"OSVDB", value:"24465");
 script_xref(name:"OSVDB", value:"26442");
 script_xref(name:"OSVDB", value:"26443");
 script_xref(name:"OSVDB", value:"26444");
 script_xref(name:"OSVDB", value:"26445");
 script_xref(name:"OSVDB", value:"26446");
 script_xref(name:"OSVDB", value:"27475");

 name["english"] = "MS06-021: Cumulative Security Update for Internet Explorer (916281)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web
client." );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the IE cumulative security update 916281. 

The remote version of IE is vulnerable to several flaws that may
allow an attacker to execute arbitrary code on the remote host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 
2003 :

http://www.microsoft.com/technet/security/Bulletin/MS06-021.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
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
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Mshtml.dll", version:"6.0.3790.536", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Mshtml.dll", version:"6.0.3790.2706", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Mshtml.dll", version:"6.0.2800.1555", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Mshtml.dll", version:"6.0.2900.2912", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Mshtml.dll", version:"6.0.2800.1555", min_version:"6.0.0.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Mshtml.dll", version:"5.0.3841.1900", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS06-021", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
