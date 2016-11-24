#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(15456);
 script_version("$Revision: 1.14 $");

 script_cve_id("CVE-2004-0206");
 script_bugtraq_id(11372);
 script_xref(name:"IAVA", value:"2004-t-0035");
 script_xref(name:"OSVDB", value:"10689");

 name["english"] = "MS04-031: Vulnerability in NetDDE Could Allow Code Execution (841533)";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through NetDDE service." );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows is affected by a vulnerability in 
Network Dynamic Data Exchange (NetDDE).

To exploit this flaw, NetDDE would have to be running and an attacker
with a specific knowledge of the vulnerability would need to send a malformed
NetDDE message to the remote host to overrun a given buffer.

A public exploit is available to exploit this vulnerability." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows NT, 2000, XP and 2003:

http://www.microsoft.com/technet/security/bulletin/ms04-031.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 summary["english"] = "Determines if hotfix 841533 has been installed";

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
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Netdde.exe", version:"5.2.3790.184", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Netdde.exe", version:"5.1.2600.1567", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"Netdde.exe", version:"5.1.2600.158", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Netdde.exe", version:"5.0.2195.6952", dir:"\system32") || 
      hotfix_is_vulnerable (os:"4.0", file:"Netdde.exe", version:"4.0.1381.7280", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS04-031", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"841533") > 0  )
	 {
 set_kb_item(name:"SMB/Missing/MS04-031", value:TRUE);
 hotfix_security_hole();
 }

