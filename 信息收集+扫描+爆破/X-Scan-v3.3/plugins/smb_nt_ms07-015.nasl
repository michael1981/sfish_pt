#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(24339);
 script_version("$Revision: 1.11 $");

 script_cve_id("CVE-2006-3877", "CVE-2007-0671");
 script_bugtraq_id(20325, 22383);
 script_xref(name:"OSVDB", value:"29448");
 script_xref(name:"OSVDB", value:"31901");
 
 name["english"] = "MS07-015: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (932554)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Office." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Office that may
allow arbitrary code to be run. 

To succeed, the attacker would have to send a rogue file to a user of
the remote computer and have it open it with Microsoft Office." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms07-015.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Determines the version of MSO.dll";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
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
if ( !office_version ) exit(0);

rootfile = hotfix_get_officecommonfilesdir();
if ( ! rootfile ) exit(1);


if ( "9.0" >< office_version )
	{
	rootfile = hotfix_get_programfilesdir();
	dll  =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Microsoft Office\Office\mso9.dll", string:rootfile);
	}
else if ( "10.0" >< office_version )
	dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Microsoft Shared\Office10\mso.dll", string:rootfile);
else if ( "11.0" >< office_version )
	dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Microsoft Shared\Office11\mso.dll", string:rootfile);

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);

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
 if ( !isnull(v) ) 
  {
  	 if ( ( v[0] == 9 &&  v[1] == 0 && v[2] == 0 && v[3] < 8960 )  ||
	      ( v[0] == 10 && v[1] == 0 && v[2] < 6825 ) ||
	      ( v[0] == 11 && v[1] == 0 && v[2] < 8122 ) ) {
 set_kb_item(name:"SMB/Missing/MS07-015", value:TRUE);
 hotfix_security_hole();
 }
  }
}

NetUseDel();
