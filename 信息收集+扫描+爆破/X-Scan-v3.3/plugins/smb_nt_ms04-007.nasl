#
# (C) Tenable Network Security
#

include("compat.inc");

if(description)
{
 script_id(12052);
 script_version("$Revision: 1.24 $");

 script_cve_id("CVE-2003-0818");
 script_bugtraq_id(9633, 9635, 13300);
 script_xref(name:"OSVDB", value:"3902");

 name["english"] = "MS04-007: ASN.1 parsing vulnerability (828028)";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote Windows host has a ASN.1 library which is vulnerable to a 
flaw which could allow an attacker to execute arbitrary code on this host.

To exploit this flaw, an attacker would need to send a specially crafted
ASN.1 encoded packet (either an IPsec session negotiation, or an HTTPS request)
with improperly advertised lengths.

A public code is available to exploit this flaw." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows NT, 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms04-007.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 summary["english"] = "Checks the version of MDAC";

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
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Msasn1.dll", version:"5.2.3790.88", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Msasn1.dll", version:"5.1.2600.1274", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"Msasn1.dll", version:"5.1.2600.119", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Msasn1.dll", version:"5.0.2195.6823", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"Msasn1.dll", version:"5.0.2195.6824", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS04-007", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"835732") > 0 &&
          hotfix_missing(name:"828028") > 0 ) 
	 {
 set_kb_item(name:"SMB/Missing/MS04-007", value:TRUE);
 hotfix_security_hole();
 }

