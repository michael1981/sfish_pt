#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(23643);
 script_version("$Revision: 1.8 $");

 script_cve_id("CVE-2006-4688", "CVE-2006-4689");
 script_bugtraq_id(20984, 21023);
 script_xref(name:"OSVDB", value:"30260");
 script_xref(name:"OSVDB", value:"30261");

 name["english"] = "MS06-066: Vulnerability in the Client Service for NetWare Could Allow Remote Code Execution (923980)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"A flaw in the client service for NetWare may allow an attacker to
execute arbitrary code on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the Client Service for NetWare
that is vulnerable to a buffer overflow.  An attacker may exploit this
to cause a denial of service by sending a malformed IPX packet to the
remote host, or to execute arbitrary code by exploiting a flaw in the
NetWare client." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-066.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
 summary["english"] = "Determines the presence of update 923980";
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
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, arch:"x86", file:"nwrdr.sys", version:"5.2.3790.588", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, arch:"x86", file:"nwrdr.sys", version:"5.2.3790.2783", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"nwrdr.sys", version:"5.1.2600.3015", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.0",       file:"nwrdr.sys", version:"5.0.2195.7110", dir:"\system32\drivers") )
 {
 set_kb_item(name:"SMB/Missing/MS06-066", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
