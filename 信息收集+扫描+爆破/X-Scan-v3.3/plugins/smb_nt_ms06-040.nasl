#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(22182);
 script_version("$Revision: 1.9 $");

 script_cve_id("CVE-2006-3439");
 script_bugtraq_id(19409);
 script_xref(name:"OSVDB", value:"27845");

 name["english"] = "MS06-040: Vulnerability in Server Service Could Allow Remote Code Execution (921883)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host due to a flaw in the
'server' service." );
 script_set_attribute(attribute:"description", value:
"The remote host is vulnerable to a buffer overrun in the 'Server'
service that may allow an attacker to execute arbitrary code on the
remote host with 'SYSTEM' privileges." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 
2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-040.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Determines the presence of update 921883";
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
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Netapi32.dll", version:"5.2.3790.559", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Netapi32.dll", version:"5.2.3790.2769", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Netapi32.dll", version:"5.1.2600.1874", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Netapi32.dll", version:"5.1.2600.2952", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Netapi32.dll", version:"5.0.2195.7105", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS06-040", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
