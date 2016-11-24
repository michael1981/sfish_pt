#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(33441);
 script_version("$Revision: 1.6 $");

 script_cve_id("CVE-2008-1447", "CVE-2008-1454");
 script_bugtraq_id(30131, 30132);
 script_xref(name:"OSVDB", value:"46777");
 script_xref(name:"OSVDB", value:"46778");

 name["english"] = "MS08-037: Vulnerabilities in DNS Could Allow Spoofing (953230)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is vulnerable to DNS spoofing attacks." );
 script_set_attribute(attribute:"description", value:
"Flaws in the remote DNS library may let an attacker send malicious DNS
responses to DNS requests made by the remote host, thereby spoofing or
redirecting internet traffic from legitimate locations." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released patches for Windows 2000, XP, and 2003 Server :

http://www.microsoft.com/technet/security/Bulletin/MS08-037.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N" );
script_end_attributes();

 
 summary["english"] = "Determines the presence of update 953230";

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


if ( hotfix_check_sp(win2003:3, win2k:6, xp:4, win2008:2, vista:2) <= 0 ) exit(0);
if ( get_kb_item("SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Services/DNS/DisplayName") )
	is_dns_svr = TRUE;
else 
	is_dns_svr = FALSE;

if (is_accessible_share())
{
 if ( 
      ( is_dns_svr && hotfix_is_vulnerable (os:"6.0", sp:1, file:"dns.exe", version:"6.0.6001.18081", dir:"\system32")) ||
      ( is_dns_svr && hotfix_is_vulnerable (os:"6.0", sp:1, file:"dns.exe", version:"6.0.6001.22192", min_version:"6.0.6001.22000", dir:"\system32")) ||
      hotfix_is_vulnerable (os:"5.2", sp:2, file:"dnsapi.dll", version:"5.2.3790.4318", dir:"\system32") ||
      ( is_dns_svr && hotfix_is_vulnerable (os:"5.2", sp:2, file:"dns.exe", version:"5.2.3790.4318", dir:"\system32")) ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"dnsapi.dll", version:"5.2.3790.3161", dir:"\system32") ||
      ( is_dns_svr && hotfix_is_vulnerable (os:"5.2", sp:1, file:"dns.exe", version:"5.2.3790.3161", dir:"\system32")) ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"dnsapi.dll", version:"5.1.2600.3394", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:3, file:"dnsapi.dll", version:"5.1.2600.5625", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"dnsapi.dll", version:"5.0.2195.7158", dir:"\system32") ||
      ( is_dns_svr && hotfix_is_vulnerable (os:"5.0", file:"dns.exe", version:"5.0.2195.7162", dir:"\system32")) )
      
 {
 set_kb_item(name:"SMB/Missing/MS08-037", value:TRUE);
 hotfix_security_warning();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
