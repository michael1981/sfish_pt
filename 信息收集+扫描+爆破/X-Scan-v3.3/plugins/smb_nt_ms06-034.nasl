#
# (C) Tenable Network Security
#

include("compat.inc");

if(description)
{
 script_id(22028);
 script_cve_id("CVE-2006-0026");
 script_bugtraq_id(18858);
 script_xref(name:"OSVDB", value:"27152");

 script_version("$Revision: 1.11 $");
 name["english"] = "MS06-034: Vulnerability in Microsoft IIS using ASP Could Allow Remote Code Execution (917537)";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to use the remote web server to exploit arbitrary code on the 
remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Windows and IIS which is vulnerable
to a flaw which may allow an attacker who has the privileges to upload 
arbitrary ASP scripts to it to execute arbitrary code.

Specifically, the remote version of IIS is vulnerable to a flaw when parsing 
specially crafted ASP files. By uploading a malicious ASP file on the remote
host, an attacker may be able to take the complete control of the remote 
system." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 2003:

http://www.microsoft.com/technet/security/bulletin/ms06-034.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P" );

script_end_attributes();

 
 summary["english"] = "Determines if hotfix 917537 has been installed";

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

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

if ( hotfix_check_iis_installed() <= 0 ) exit(0);
if ( hotfix_check_sp(win2k:6, xp:3, win2003:2) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:1, file:"asp.dll", version:"6.0.3790.2684", dir:"\system32\inetsrv") ||
      hotfix_is_vulnerable (os:"5.2", sp:0, file:"asp.dll", version:"6.0.3790.520", dir:"\system32\inetsrv") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"asp.dll", version:"5.1.2600.2889", dir:"\system32\inetsrv") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"asp.dll", version:"5.1.2600.1829", dir:"\system32\inetsrv") ||
      hotfix_is_vulnerable (os:"5.0", file:"asp.dll", version:"5.0.2195.7084", dir:"\system32\inetsrv") )
 {
 set_kb_item(name:"SMB/Missing/MS06-034", value:TRUE);
 hotfix_security_warning();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
