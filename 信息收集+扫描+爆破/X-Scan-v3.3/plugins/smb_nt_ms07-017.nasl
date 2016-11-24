#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(24911);
 script_version("$Revision: 1.10 $");

 script_cve_id(
  "CVE-2006-5586",
  "CVE-2006-5758",
  "CVE-2007-0038",
  "CVE-2007-1211",
  "CVE-2007-1212",
  "CVE-2007-1213",
  "CVE-2007-1215",
  "CVE-2007-1765"
 );
 script_bugtraq_id(23194, 23273, 23275, 23276, 23277, 23278);
 script_xref(name:"OSVDB", value:"33629");
 script_xref(name:"OSVDB", value:"34095");
 script_xref(name:"OSVDB", value:"34096");
 script_xref(name:"OSVDB", value:"34097");
 script_xref(name:"OSVDB", value:"34098");
 script_xref(name:"OSVDB", value:"34099");

 name["english"] = "MS07-017: Vulnerabilities in GDI Could Allow Remote Code Execution (925902)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the email
client or the web browser." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Windows with a bug in the
Animated Cursor (ANI) handling routine that may allow an attacker
execute arbitrary code on the remote host by sending a specially
crafted email or by luring a user on the remote host into visiting a
rogue web site. 

Additionally, the system is vulnerable to :

  - Local Privilege Elevation (GDI, EMF, Font Rasterizer)

  - Denial of Service (WMF)" );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003 and
Vista :

http://www.microsoft.com/technet/security/Bulletin/MS07-017.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Determines the presence of update 925902";
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
 if ( hotfix_is_vulnerable (os:"6.0", sp:0, file:"User32.dll", version:"6.0.6000.16438", dir:"\System32") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"User32.dll", version:"6.0.6000.20537", min_version:"6.0.6000.20000", dir:"\System32") ||
      hotfix_is_vulnerable (os:"5.2", sp:2, file:"User32.dll", version:"5.2.3790.4033", dir:"\System32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"User32.dll", version:"5.2.3790.2892", dir:"\System32") ||
      hotfix_is_vulnerable (os:"5.2", sp:0, file:"User32.dll", version:"5.2.3790.651", dir:"\System32") ||
      hotfix_is_vulnerable (os:"5.1", file:"User32.dll", version:"5.1.2600.3099", dir:"\System32") ||
      hotfix_is_vulnerable (os:"5.0", file:"User32.dll", version:"5.0.2195.7133", dir:"\System32") )
 {
 set_kb_item(name:"SMB/Missing/MS07-017", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
