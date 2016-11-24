#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(11177);
 script_bugtraq_id(6371,6372,6379,6380);
 script_version("$Revision: 1.24 $");
 script_cve_id("CVE-2002-1257","CVE-2002-1258","CVE-2002-1260","CVE-2002-1292","CVE-2002-1295","CVE-2002-1325");
 script_xref(name:"IAVA", value:"2003-b-0002");
 script_xref(name:"IAVA", value:"2003-b-0008");
 script_xref(name:"OSVDB", value:"11914");
 script_xref(name:"OSVDB", value:"13417");

 name["english"] = "MS02-052: Flaw in Microsoft VM Could Allow Code Execution (810030)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the VM." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a Microsoft VM machine which has a bug
in its bytecode verifier which may allow a remote attacker to execute
arbitrary code on this host, with the privileges of the SYSTEM.

To exploit this vulnerability, an attacker would need to send a malformed
applet to a user on this host, and have him execute it. The malicious
applet would then be able to execute code outside the sandbox of the VM." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows NT, 2000 and XP :

http://www.microsoft.com/technet/security/bulletin/ms02-069.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();


 summary["english"] = "Checks for MS Hotfix Q329077, Flaw in Microsoft VM JDBC";

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

include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

if ( hotfix_check_sp(nt:7, xp:2, win2k:4) <= 0 ) exit(0);

version = get_kb_item ("SMB/Registry/HKLM/SOFTWARE/Microsoft/Active Setup/Installed Components/{08B0E5C0-4FCB-11CF-AAA5-00401C608500}/Version");
if (!version) exit(0);

v = split(version, sep:",", keep:FALSE);
if ( int(v[0]) < 5 ||
     ( int(v[0]) == 5 && int(v[1]) == 0 && int(v[2]) < 3807) )
{
 if ( hotfix_missing(name:"810030") > 0 )
 {
 set_kb_item(name:"SMB/Missing/MS02-052", value:TRUE);
 hotfix_security_hole();
 }
}
