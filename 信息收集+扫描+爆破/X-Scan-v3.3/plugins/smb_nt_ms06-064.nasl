#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(22537);
 script_version("$Revision: 1.7 $");

 script_cve_id("CVE-2004-0790","CVE-2004-0230","CVE-2005-0688");
 script_bugtraq_id(13124, 13658);
 script_xref(name:"OSVDB", value:"4030");
 script_xref(name:"OSVDB", value:"14578");
 script_xref(name:"OSVDB", value:"15457");

 name["english"] = "MS06-064: Vulnerability in TCP/IP IPv6 Could Allow Denial of Service (922819)";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to crash the remote host due to a flaw in the TCP/IP
IPv6 stack." );
 script_set_attribute(attribute:"description", value:
"The remote host runs a version of Windows that has a flaw in its
TCP/IP IPv6 stack. 

The flaw may allow an attacker to perform a denial of service attack
against the remote host. 

To exploit this vulnerability, an attacker needs to send a specially
crafted ICMP or TCP packet to the remote host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-064.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
script_end_attributes();

 
 summary["english"] = "Checks the remote registry for 922819";
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
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Tcpip6.sys", version:"5.2.3790.576", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Tcpip6.sys", version:"5.2.3790.2771", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Tcpip6.sys", version:"5.1.2600.1886", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Tcpip6.sys", version:"5.1.2600.2975", dir:"\system32\drivers") )
 {
 set_kb_item(name:"SMB/Missing/MS06-064", value:TRUE);
 security_warning(get_kb_item("SMB/transport"));
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
