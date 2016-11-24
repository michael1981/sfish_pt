#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(20907);
 script_version("$Revision: 1.13 $");

 script_cve_id("CVE-2006-0021");
 script_bugtraq_id(16645);
 script_xref(name:"OSVDB", value:"23133");

 name["english"] = "MS06-007: Vulnerability in TCP/IP Could Allow Denial of Service (913446)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to crash the remote host due to a flaw in the TCP/IP
stack." );
 script_set_attribute(attribute:"description", value:
"The remote host runs a version of Windows with a flaw in its TCP/IP
stack that may allow an attacker to perform a denial of service attack
against the remote host. 

To exploit this vulnerability, an attacker needs to send a specially
crafted IGMP packet to the remote host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 
2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-007.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
script_end_attributes();

 
 summary["english"] = "Checks the remote registry for 913446";
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


if ( hotfix_check_sp(xp:3, win2003:2) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Tcpip.sys", version:"5.2.3790.468", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Tcpip.sys", version:"5.2.3790.2617", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Tcpip.sys", version:"5.1.2600.1792", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Tcpip.sys", version:"5.1.2600.2827", dir:"\system32\drivers") )
 {
 set_kb_item(name:"SMB/Missing/MS06-007", value:TRUE);
 hotfix_security_warning();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
