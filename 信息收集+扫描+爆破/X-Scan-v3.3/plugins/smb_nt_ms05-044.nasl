#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(19997);
 script_version("$Revision: 1.11 $");

 script_cve_id("CVE-2005-2126");
 script_xref(name:"IAVA", value:"2004-t-0036");
 script_xref(name:"IAVA", value:"2005-t-0041");
 script_xref(name:"OSVDB", value:"19901");

 name["english"] = "MS05-044: Vulnerability in the Windows FTP Client Could Allow File Transfer Location Tampering (905495)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"A flaw in the FTP client installed on the remote host may allow a
rogue FTP server to write to arbitrary locations on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the Microsoft FTP client that
contains a flaw in the way it handles FTP download.  An attacker may
exploit this flaw to modify the destination location for files
downloaded via FTP. 

To exploit this flaw an attacker would need to set up a rogue FTP
server and have a victim on the remote host connect to it and download
a file manually using the affected client." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 
2003 :

http://www.microsoft.com/technet/security/bulletin/ms05-044.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 
 summary["english"] = "Determines the presence of update 905495";
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

version = hotfix_check_ie_version ();
if (!version || !egrep (pattern:"^6\.", string:version)) exit (0);

if ( hotfix_check_sp(xp:2, win2003:1, win2k:6) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"msieftp.dll", version:"6.0.3790.383", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"msieftp.dll", version:"6.0.2800.1724", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0",       file:"msieftp.dll", version:"5.50.4956.500", min_version:"5.50.0.0", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS05-044", value:TRUE);
 hotfix_security_note();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"905495") > 0 ) {
 set_kb_item(name:"SMB/Missing/MS05-044", value:TRUE);
 hotfix_security_note();
 }
