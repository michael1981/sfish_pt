#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(21213);
 script_version("$Revision: 1.9 $");

 script_cve_id("CVE-2006-0014");
 script_bugtraq_id(17459);
 script_xref(name:"OSVDB", value:"24519");

 name["english"] = "MS06-016: Vulnerability in Outlook Express Could Allow Remote Code Execution (911567)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the email
client." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Outlook Express that
may allow an attacker to execute arbitrary code on the remote host. 

To exploit this flaw, an attacker would need to send a malformed
Windows Address Book (.wab) file to a victim on the remote host and
have him open the file." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Outlook Express :

See: http://www.microsoft.com/technet/security/bulletin/ms06-016.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
 summary["english"] = "Determines the version of MSOE.dll";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/WindowsVersion");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

if ( hotfix_check_sp(xp:3, win2k:6, win2003:2) <= 0 ) exit(0);

if ( is_accessible_share() )
{
 path = hotfix_get_programfilesdir() + '\\Outlook Express\\';

if ( hotfix_is_vulnerable(os:"5.2", sp:0, file:"msoe.dll", version:"6.0.3790.504", path:path) ||
     hotfix_is_vulnerable(os:"5.2", sp:1, file:"msoe.dll", version:"6.0.3790.2663", path:path) ||
     hotfix_is_vulnerable(os:"5.1", sp:1, file:"msoe.dll", version:"6.0.2800.1807", path:path) ||
     hotfix_is_vulnerable(os:"5.1", sp:2, file:"msoe.dll", version:"6.0.2900.2869", path:path) ||
     hotfix_is_vulnerable(os:"5.0", file:"msoe.dll", version:"6.0.2800.1807", min_version:"6.0.0.0", path:path) ||
     hotfix_is_vulnerable(os:"5.0", file:"msoe.dll", version:"5.50.4963.1700", path:path) )
	 {
 set_kb_item(name:"SMB/Missing/MS06-016", value:TRUE);
 hotfix_security_warning();
 }

 hotfix_check_fversion_end();
}
