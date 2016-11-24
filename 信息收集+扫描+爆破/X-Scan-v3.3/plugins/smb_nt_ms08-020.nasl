#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(31793);
 script_version("$Revision: 1.9 $");

 script_cve_id("CVE-2008-0087");
 script_bugtraq_id(28553);
 script_xref(name:"OSVDB", value:"44172");

 name["english"] = "MS08-020: Vulnerability in DNS Client Could Allow Spoofing (945553)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is vulnerable to DNS spoofing." );
 script_set_attribute(attribute:"description", value:
"There is a flaw in the remote DNS client which may let an attacker send 
malicious DNS responses to DNS requests made by the remote host, thereby
spoofing or redirecting internet traffic from legitimate locations." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released patches for Windows 2000, XP, 2003 Server and Vista :

http://www.microsoft.com/technet/security/Bulletin/MS08-020.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N" );




script_end_attributes();

 
 summary["english"] = "Determines the presence of update 945553";

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


if ( hotfix_check_sp(win2003:3, win2k:6, xp:3, vista:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( 
     hotfix_is_vulnerable (os:"6.0", sp:0, file:"dnsapi.dll", version:"6.0.6000.16615", dir:"\system32") ||
     hotfix_is_vulnerable (os:"6.0", sp:0, file:"dnsapi.dll", version:"6.0.6000.20740", min_version:"6.0.6000.20000", dir:"\system32") ||
     hotfix_is_vulnerable (os:"5.2", sp:2, file:"dnsapi.dll", version:"5.2.3790.4238", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"dnsapi.dll", version:"5.2.3790.3092", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"dnsapi.dll", version:"5.1.2600.3316", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"dnsapi.dll", version:"5.0.2195.7151", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS08-020", value:TRUE);
 hotfix_security_warning();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
