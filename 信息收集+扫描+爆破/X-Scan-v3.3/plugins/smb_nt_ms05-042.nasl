#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(19405);
 script_version("$Revision: 1.15 $");

 script_cve_id("CVE-2005-1981", "CVE-2005-1982");
 script_bugtraq_id (14519, 14520);
 script_xref(name:"OSVDB", value:"18608");
 script_xref(name:"OSVDB", value:"18609");

 name["english"] = "MS05-042: Vulnerability in Kerberos Could Allow Denial of Service, Information Disclosure and Spoofing (899587)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to crash the remote service or disclose information." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the Kerberos protocol that
contains multiple security flaws that may allow an attacker to crash
the remote service (AD), disclose information or spoof a session. 

An attacker would need valid credentials to exploit these flaws." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 
2003 :

http://www.microsoft.com/technet/security/bulletin/ms05-042.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:S/C:P/I:P/A:P" );
script_end_attributes();

 
 summary["english"] = "Determines the presence of update 899587";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
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
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"kerberos.dll", version:"5.2.3790.347", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"kerberos.dll", version:"5.2.3790.2464", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"kerberos.dll", version:"5.1.2600.1701", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"kerberos.dll", version:"5.1.2600.2698", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", sp:4, file:"kerberos.dll", version:"5.0.2195.7053", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS05-042", value:TRUE);
 hotfix_security_warning();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
