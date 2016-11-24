#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(21693);
 script_version("$Revision: 1.9 $");
 script_cve_id("CVE-2006-2380");
 script_bugtraq_id(18389);
 script_xref(name:"OSVDB", value:"26438");

 name["english"] = "MS06-031: Vulnerability in RPC Mutual Authentication Could Allow Spoofing (917736)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to spoof an RPC server." );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a version of SMB (Server
Message Block) protocol which is vulnerable to a spoofing attack.

An attacker may exploit these flaws to enduce a user to connect to
a malicious RPC server." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000 :

http://www.microsoft.com/technet/security/bulletin/ms06-031.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 
 summary["english"] = "Determines the presence of update 917736";

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


if ( hotfix_check_sp(win2k:6) <= 0 ) exit(0);
if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.0",       file:"Rpcrt4.dll", version:"5.0.2195.7085", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS06-031", value:TRUE);
 hotfix_security_warning();
 }
      hotfix_check_fversion_end(); 
}
else if ( hotfix_missing(name:"917736") > 0 &&
	hotfix_missing(name:"933729") > 0 ) 
 {
 set_kb_item(name:"SMB/Missing/MS06-031", value:TRUE);
 hotfix_security_warning();
 }
