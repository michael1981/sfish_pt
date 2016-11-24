#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(16332);
 script_version("$Revision: 1.14 $");

 script_cve_id("CVE-2004-0848");
 script_bugtraq_id(12480);
 script_xref(name:"OSVDB", value:"13594");

 name["english"] = "MS05-005: Vulnerability in Microsoft Office XP could allow Remote Code Execution (873352)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the Office client." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Office that may
allow an attacker to execute arbitrary code on the remote host. 

To exploit this flaw, an attacker would need to send a specially
crafted file to a user on the remote host and wait for him to open it
using Microsoft Office. 

When opening the malformed file, Microsoft Office will encounter a
buffer overflow which may be exploited to execute arbitrary code." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a patch for Office XP :

http://www.microsoft.com/technet/security/bulletin/ms05-005.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Determines the version of MSO.dll";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
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
if ( ! get_kb_item("SMB/WindowsVersion") ) exit(1);

office_version = hotfix_check_office_version ();
if ( !office_version || (office_version >!< "10.0"))
{
  if ( ! hotfix_check_works_installed () )
    exit (0);

  version = get_kb_item("SMB/Works/Version");
  if (!version || (version != "6.0" && version != "7.0"))
    exit (0);
}

rootfile = hotfix_get_commonfilesdir();
if ( ! rootfile ) exit(1);

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);
dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Microsoft Shared\Office10\mso.dll", string:rootfile);


name 	=  kb_smb_name();
login	=  kb_smb_login();
pass  	=  kb_smb_password();
domain 	=  kb_smb_domain();
port    =  kb_smb_transport();

if(!get_port_state(port))exit(1);

soc = open_sock_tcp(port);
if(!soc)exit(1);


session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 ) exit(1);


handle =  CreateFile (file:dll, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

if ( ! isnull(handle) )
{
 v = GetFileVersion(handle:handle);
 CloseFile(handle:handle);
 if ( v[0] == 10 &&  v[1] ==  0 && v[2] < 6735  )
	 {
 set_kb_item(name:"SMB/Missing/MS05-005", value:TRUE);
 hotfix_security_hole();
 }
}

NetUseDel();
