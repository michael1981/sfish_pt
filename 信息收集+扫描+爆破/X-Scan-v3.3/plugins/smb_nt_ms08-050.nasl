#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(33879);
 script_version("$Revision: 1.5 $");

 script_cve_id("CVE-2008-0082");
 script_bugtraq_id(30551);
 script_xref(name:"OSVDB", value:"47403");
 
 name["english"] = "MS08-050: Vulnerability in Windows Messenger Could Allow Information Disclosure (955702)";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is vulnerable to an information disclosure due to
Windows Messenger" );
 script_set_attribute(attribute:"description", value:
"The remote host is running Windows Messenger. 

There is a vulnerability in the remote version of this software which
may lead to an information disclosure which may allow an attacker to
change the state of a user, to get contact informations or to
initiation audio and video chat sessions." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms08-050.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 
 summary["english"] = "Checks the version of Windows Messenger";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_full_access","SMB/WindowsVersion");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

port = get_kb_item("SMB/transport");
if(!port) port = 139;


if ( hotfix_check_sp(xp:4, win2k:5, win2003:1) <= 0 ) exit(0);

if (is_accessible_share())
 {
   rootfile = hotfix_get_programfilesdir();
   if ( 
       hotfix_is_vulnerable (os:"5.1", file:"Msgsc.dll", version:"4.7.0.3002", path:rootfile, dir:"\Messenger") ||
       hotfix_is_vulnerable (os:"5.2", file:"Msgsc.dll", version:"4.7.0.3002", path:rootfile, dir:"\Messenger") )
 {
 set_kb_item(name:"SMB/Missing/MS08-050", value:TRUE);
 hotfix_security_warning();
 }
   hotfix_check_fversion_end(); 
 }

