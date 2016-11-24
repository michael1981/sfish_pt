#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(13641);
 script_version("$Revision: 1.16 $");

 script_cve_id("CVE-2004-0201", "CVE-2003-1041");
 script_bugtraq_id(10705, 9320);
 script_xref(name:"IAVA", value:"2004-A-0012");
 script_xref(name:"OSVDB", value:"7803");
 script_xref(name:"OSVDB", value:"7804");
 script_xref(name:"OSVDB", value:"7912");

 name["english"] = "MS04-023: Vulnerability in HTML Help Could Allow Code Execution (840315)";
 script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web
client." );
 script_set_attribute(attribute:"description", value:
"The remote host is subject to two vulnerabilities in the HTML Help and
showHelp modules that could allow an attacker to execute arbitrary
code on the remote host. 

To exploit these flaws, an attacker would need to set up a rogue
website containing a malicious showHelp URL, and would need to lure a
user on the remote host to visit it.  Once the user visits the web
site, a buffer overflow would allow the attacker to execute arbitrary
commands with the privileges of the victim user." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 
2003 :

http://www.microsoft.com/technet/security/bulletin/ms04-023.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Checks for ms04-023 over the registry";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
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

if ( hotfix_check_sp(nt:7, win2k:5, xp:2, win2003:1) <= 0 ) exit(0);


if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:1, file:"Itss.dll", version:"5.2.3790.185", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Itss.dll", version:"5.2.3790.185", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"Itss.dll", version:"5.2.3790.185", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Itss.dll", version:"5.2.3790.185", dir:"\system32") || 
      hotfix_is_vulnerable (os:"4.0", file:"Itss.dll", version:"5.2.3790.185", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS04-023", value:TRUE);
 security_hole(get_kb_item("SMB/transport"));
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"840315") > 0 && hotfix_missing(name:"896358") > 0  )
	 {
 set_kb_item(name:"SMB/Missing/MS04-023", value:TRUE);
 hotfix_security_hole();
 }

