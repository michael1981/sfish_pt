#
# (C) Tenable Network Security
#

include("compat.inc");

if(description)
{
 script_id(18023);
 script_version("$Revision: 1.16 $");

 script_cve_id(
  "CVE-2004-0230",
  "CVE-2004-0790",
  "CVE-2004-1060",
  "CVE-2005-0048",
  "CVE-2005-0065",
  "CVE-2005-0066",
  "CVE-2005-0067",
  "CVE-2005-0068",
  "CVE-2005-0688"
 );
 script_bugtraq_id(13116, 13124, 13658);
 script_xref(name:"IAVA", value:"2005-B-0011");
 script_xref(name:"IAVA", value:"2005-B-0012");
 script_xref(name:"OSVDB", value:"14578");
 script_xref(name:"OSVDB", value:"15457");
 script_xref(name:"OSVDB", value:"15619");

 name["english"] = "MS05-019: Vulnerabilities in TCP/IP Could Allow Remote Code Execution (893066)";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host due to a flaw in the 
TCP/IP stack." );
 script_set_attribute(attribute:"description", value:
"The remote host runs a version of Windows which has a flaw in its TCP/IP
stack.

The flaw may allow an attacker to execute arbitrary code with SYSTEM
privileges on the remote host, or to perform a denial of service attack
against the remote host.

Proof of concept code is available to perform a Denial of Service against
a vulnerable system." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms05-019.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C" );

script_end_attributes();

 
 summary["english"] = "Checks the remote registry for 893066";

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

include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");


if ( hotfix_check_sp(xp:3, win2k:5, win2003:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Tcpip.sys", version:"5.2.3790.336", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Tcpip.sys", version:"5.1.2600.1693", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Tcpip.sys", version:"5.1.2600.2685", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.0", file:"Tcpip.sys", version:"5.0.2195.7049", dir:"\system32\drivers") )
 {
 set_kb_item(name:"SMB/Missing/MS05-019", value:TRUE);
 security_hole(get_kb_item("SMB/transport"));
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else
{
 if (hotfix_missing(name:"893066") > 0 &&  
     hotfix_missing(name:"913446") > 0 && 
     hotfix_missing(name:"917953") > 0 &&
     hotfix_missing(name:"941644") > 0 &&
     hotfix_missing(name:"946456") > 0 )
 {
 set_kb_item(name:"SMB/Missing/MS05-019", value:TRUE);
 hotfix_security_hole();
 }
}
