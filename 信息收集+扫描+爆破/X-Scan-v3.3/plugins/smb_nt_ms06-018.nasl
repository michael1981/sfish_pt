#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(21331);
 script_bugtraq_id (17905, 17906);
 script_version("$Revision: 1.10 $");
 script_cve_id("CVE-2006-1184", "CVE-2006-0034");
 script_xref(name:"OSVDB", value:"25335");
 script_xref(name:"OSVDB", value:"25336");

 name["english"] = "MS06-018: Vulnerability in MSDTC Could Allow Denial of Service (913580)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to crash the remote MSDTC service." );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a version of MSDTC that
contains several denial of service vulnerabilities (DoS and Invalid
Memory Access). 

An attacker may exploit these flaws to crash the remote service." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 
2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-018.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
 summary["english"] = "Determines the presence of update 913580";
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

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


if ( hotfix_check_sp(xp:3, win2003:1, win2k:6) <= 0 ) exit(0);
if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Msdtctm.dll", version:"2001.12.4720.480", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Msdtctm.dll", version:"2001.12.4414.65", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Msdtctm.dll", version:"2001.12.4414.311", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0",       file:"Msdtctm.dll", version:"2000.2.3535.0", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS06-018", value:TRUE);
 hotfix_security_hole();
 }
      hotfix_check_fversion_end(); 
}
else if ( hotfix_missing(name:"913580") > 0 ) {
 set_kb_item(name:"SMB/Missing/MS06-018", value:TRUE);
 hotfix_security_hole();
 }
