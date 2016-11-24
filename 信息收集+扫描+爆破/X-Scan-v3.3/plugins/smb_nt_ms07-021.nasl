#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(25024);
 script_version("$Revision: 1.11 $");

 script_cve_id("CVE-2006-6696", "CVE-2006-6797", "CVE-2007-1209");
 script_bugtraq_id(21688, 23324, 23338);
 script_xref(name:"OSVDB", value:"31659");
 script_xref(name:"OSVDB", value:"31897");
 script_xref(name:"OSVDB", value:"34008");

 name["english"] = "MS07-021: Vulnerabilities in CSRSS Could Allow Remote Code Execution (930178)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web
browser." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Windows containing a bug in
the CSRSS error message handling routine that may allow an attacker to
execute arbitrary code on the remote host by luring a user on the
remote host into visiting a rogue web site. 

Additionally, the system is prone to the following types of attack :

- Local Priviledge Elevation
- Denial of Service (Local)" );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003 and
Vista :

http://www.microsoft.com/technet/security/Bulletin/MS07-021.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Determines the presence of update 930178";

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
 if ( hotfix_is_vulnerable (os:"6.0", sp:0, file:"Winsrv.dll", version:"6.0.6000.16445", dir:"\System32") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"Winsrv.dll", version:"6.0.6000.20522", min_version:"6.0.6000.20000", dir:"\System32") ||
      hotfix_is_vulnerable (os:"5.2", sp:2, file:"Winsrv.dll", version:"5.2.3790.4043", dir:"\System32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Winsrv.dll", version:"5.2.3790.2902", dir:"\System32") ||
      hotfix_is_vulnerable (os:"5.2", sp:0, file:"Winsrv.dll", version:"5.2.3790.658", dir:"\System32") ||
      hotfix_is_vulnerable (os:"5.1", file:"Winsrv.dll", version:"5.1.2600.3103", dir:"\System32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Winsrv.dll", version:"5.0.2195.7135", dir:"\System32") )
 {
 set_kb_item(name:"SMB/Missing/MS07-021", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
