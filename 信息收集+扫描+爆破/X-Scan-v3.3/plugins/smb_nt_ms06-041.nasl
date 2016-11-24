#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(22183);
 script_version("$Revision: 1.11 $");

 script_cve_id("CVE-2006-3440", "CVE-2006-3441");
 script_bugtraq_id(19319, 19404);
 script_xref(name:"OSVDB", value:"27843");
 script_xref(name:"OSVDB", value:"27844");

 name["english"] = "MS06-041: Vulnerability in DNS Resolution Could Allow Remote Code Execution (920683)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host due to a flaw in the
DNS client." );
 script_set_attribute(attribute:"description", value:
"The remote host is vulnerable to a buffer overrun in the DNS client
service, which may allow an attacker to execute arbitrary code on the
remote host with SYSTEM privileges. 

To exploit this vulnerability, an attacker would need to set up a
rogue DNS server to reply to the client with a specially crafted
packet." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 
2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-041.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Determines the presence of update 920683";
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


if ( hotfix_check_sp(xp:3, win2003:2, win2k:6) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( 
      hotfix_is_vulnerable (os:"5.2", sp:0, file:"Dnsapi.dll", version:"5.2.3790.558", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Dnsapi.dll", version:"5.2.3790.2745", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Dnsapi.dll", version:"5.1.2600.1863", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Dnsapi.dll", version:"5.1.2600.2938", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Dnsapi.dll", version:"5.0.2195.7100", dir:"\system32") ||

      hotfix_is_vulnerable (os:"5.2", sp:0, file:"Rasadhlp.dll", version:"5.2.3790.558", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Rasadhlp.dll", version:"5.2.3790.2745", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Rasadhlp.dll", version:"5.1.2600.1863", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Rasadhlp.dll", version:"5.1.2600.2938", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Rasadhlp.dll", version:"5.0.2195.7098", dir:"\system32") 
 )
 {
 set_kb_item(name:"SMB/Missing/MS06-041", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}

