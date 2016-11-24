#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(33136);
 script_version("$Revision: 1.7 $");

 script_cve_id("CVE-2008-1451");
 script_bugtraq_id(29588);
 script_xref(name:"OSVDB", value:"46063");

 name["english"] = "MS08-034: Vulnerability in WINS Could Allow Elevation of Privilege (948745)";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote WINS service can be abused to escalate privileges." );
 script_set_attribute(attribute:"description", value:
"The remote Windows Internet Naming Service (WINS) is vulnerable to a
memory overwrite attack that could allow a local attacker to elevate
his privileges on the remote host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000 and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms08-034.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 summary["english"] = "Checks the remote host for MS08-034";

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


if ( hotfix_check_wins_installed() <= 0 ) exit(0);
if ( hotfix_check_sp(win2k:6, win2003:3) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:1, file:"Wins.exe", version:"5.2.3790.3119", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:2, file:"Wins.exe", version:"5.2.3790.4271", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Wins.exe", version:"5.0.2195.7155", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS08-034", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
