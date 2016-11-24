#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(22332);
 script_version("$Revision: 1.10 $");

 script_cve_id("CVE-2006-3442");
 script_bugtraq_id(19922);
 script_xref(name:"OSVDB", value:"28731");

 name["english"] = "MS06-052: Vulnerability in Pragmatic General Multicast (PGM) Could Allow Remote Code Execution (919007)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows is affected by a vulnerability in the
Pragmatic General Multicast protocol installed with the MSMQ service. 

An attacker may exploit this flaw to execute arbitrary code on the
remote host with KERNEL privileges." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP :

http://www.microsoft.com/technet/security/bulletin/ms06-052.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
 summary["english"] = "Determines if hotfix 919007 has been installed";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);

 script_dependencies("smb_hotfixes.nasl" );
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");

if ( hotfix_check_sp(xp:3) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", sp:1, file:"Rmcast.sys", version:"5.1.2600.1873", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Rmcast.sys", version:"5.1.2600.2951", dir:"\system32\drivers") )
 {
 set_kb_item(name:"SMB/Missing/MS06-052", value:TRUE);
 hotfix_security_warning();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"919007") > 0  )
 {
 set_kb_item(name:"SMB/Missing/MS06-052", value:TRUE);
 hotfix_security_warning();
 }
