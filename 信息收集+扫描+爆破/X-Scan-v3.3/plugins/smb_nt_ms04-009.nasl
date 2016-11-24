#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(12092);
 script_version("$Revision: 1.14 $");

 script_cve_id("CVE-2004-0121");
 script_bugtraq_id(9827);
 script_xref(name:"IAVA", value:"2004-B-0004");
 script_xref(name:"OSVDB", value:"4168");

 name["english"] = "MS04-009: Vulnerability in Outlook could allow code execution (828040)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the email
client." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of outlook that may allow
Internet Explorer to execute script code in the Local Machine zone and
therefore let an attacker execute arbitrary programs on this host. 

To exploit this bug, an attacker would need to send an special HTML
message to a user of this host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2002 and XP :

http://www.microsoft.com/technet/security/bulletin/ms04-009.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Determines the version of OutLook.exe";
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

CommonFilesDir = hotfix_get_commonfilesdir();
if ( ! CommonFilesDir ) exit(1);





login	=  kb_smb_login();
pass  	=  kb_smb_password();
domain 	=  kb_smb_domain();
port    =  kb_smb_transport();
if(!get_port_state(port))exit(1);

soc = open_sock_tcp(port);
if(!soc)exit(1);

session_init(socket:soc, hostname:kb_smb_name());
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(1);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) )
{
 NetUseDel();
 exit(1);
}

key_h = RegOpenKey(handle:hklm, key:"SOFTWARE\Microsoft\Office\10.0\Outlook\InstallRoot", mode:MAXIMUM_ALLOWED);
if ( isnull(key_h) )
{
 RegCloseKey(handle:hklm);
 NetUseDel();
 exit(1);
}

value = RegQueryValue(handle:key_h, item:"Path");
RegCloseKey(handle:key_h);
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

if ( isnull(value) ) 
{
 NetUseDel();
 exit(1);
}


share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:value[1]);
outlook =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\outlook.exe", string:value[1]);

r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 )
{
 NetUseDel();
 exit(1);
}

handle =  CreateFile (file:outlook, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

if ( ! isnull(handle) )
{
 v = GetFileVersion(handle:handle);
 CloseFile(handle:handle);
 if ( ! isnull(v) )
 {
  if ( v[0] == 10 && v[1] == 0 && v[2] < 5709 ) {
 set_kb_item(name:"SMB/Missing/MS04-009", value:TRUE);
 hotfix_security_hole();
 }
 }
}

NetUseDel();

