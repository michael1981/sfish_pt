#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(31038);
 script_version("$Revision: 1.5 $");

 script_cve_id("CVE-2008-0084");
 script_bugtraq_id(27634);

 name["english"] = "MS08-004: Vulnerability in Windows TCP/IP Could Allow Denial of Service (946456)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to execute code on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a version of the TCP/IP 
protocol which does not properly parse DHCP packets.

An attacker may exploit these flaws to crash the remote host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista :

http://www.microsoft.com/technet/security/bulletin/ms08-004.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 
 summary["english"] = "Determines the presence of update 946456";

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


if ( hotfix_check_sp(vista:1) <= 0 ) exit(0);
if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"6.0", sp:0, file:"Tcpip.sys", version:"6.0.6000.20752", min_version:"6.0.6000.20000", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"Tcpip.sys", version:"6.0.6000.16627", dir:"\system32\drivers") )
      	 {
 set_kb_item(name:"SMB/Missing/MS08-004", value:TRUE);
 hotfix_security_note();
 }
      hotfix_check_fversion_end(); 
}
else if ( hotfix_missing(name:"946456") > 0 ) {
 set_kb_item(name:"SMB/Missing/MS08-004", value:TRUE);
 hotfix_security_note();
 }
