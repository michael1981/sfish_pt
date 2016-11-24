#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(29893);
 script_version("$Revision: 1.9 $");

 script_cve_id("CVE-2007-0066", "CVE-2007-0069");
 script_bugtraq_id(27100, 27139);
 script_xref(name:"OSVDB", value:"40069");
 script_xref(name:"OSVDB", value:"40070");

 name["english"] = "MS08-001: Vulnerabilities in Windows TCP/IP Could Allow Remote Code Execution (941644)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to execute code on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a version of the TCP/IP 
protocol which does not properly parse IGMPv3, MLDv2 and ICMP
structure.

An attacker may exploit these flaws to execute code on the remote
host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003 and Vista :

http://www.microsoft.com/technet/security/bulletin/ms08-001.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 summary["english"] = "Determines the presence of update 941644";

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

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


if ( hotfix_check_sp(xp:3, win2003:3, win2k:6, vista:1) <= 0 ) exit(0);
if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"6.0", sp:0, file:"Tcpip.sys", version:"6.0.6000.20689", min_version:"6.0.6000.20000", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"Tcpip.sys", version:"6.0.6000.16567", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Tcpip.sys", version:"5.2.3790.3036", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.2", sp:2, file:"Tcpip.sys", version:"5.2.3790.4179", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Tcpip.sys", version:"5.1.2600.3244", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.0",       file:"Tcpip.sys", version:"5.0.2195.7147", dir:"\system32\drivers") )
 {
 set_kb_item(name:"SMB/Missing/MS08-001", value:TRUE);
 hotfix_security_hole();
 }
      hotfix_check_fversion_end(); 
}
