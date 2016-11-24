#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(11330);
  script_bugtraq_id(1281);
  script_xref(name:"IAVA", value:"2000-t-0008");
  script_xref(name:"OSVDB", value:"557");
  script_cve_id("CVE-2000-0402");
  script_version("$Revision: 1.15 $");

  script_name(english:"MS00-035: MS SQL7.0 Service Pack may leave passwords on system (263968)");
  script_summary(english: "Reads %temp%\sqlsp.log");

   script_set_attribute(
    attribute:'synopsis',
    value:'The remote SQL server is vulner able to information disclosure.'
  );

  script_set_attribute(
    attribute:'description',
    value:'The installation process of the remote MS SQL server left
files named \'sqlsp.log\' on the remote host.

These files contain the password assigned to the \'sa\' account
of the remote database.

An attacker may use this flaw to gain full administrative
access to your database.'
  );

  script_set_attribute(
    attribute:'solution',
    value:'Apply the appropriate patches from MS00-035 or upgrade MS SQL.'
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://www.microsoft.com/technet/security/bulletin/ms00-035.mspx'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N'
  );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
  script_family(english:"Windows : Microsoft Bulletins");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys( "SMB/WindowsVersion", "SMB/registry_access");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");



common = hotfix_get_systemroot();
if ( ! common ) exit(1);

port = kb_smb_transport();
if ( ! get_port_state(port) ) exit(1);

soc = open_sock_tcp(port);
if ( ! soc ) exit(1);

login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

session_init(socket:soc, hostname:kb_smb_name());
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(1);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) )
{
 NetUseDel();
 exit(1);
}

key_h = RegOpenKey(handle:hklm, key:"SYSTEM\CurrentControlSet\Control\Session Manager\Environment", mode:MAXIMUM_ALLOWED);
if ( isnull(key_h) )
{
 RegCloseKey(handle:hklm);
 NetUseDel();
 exit(0);
}

value = RegQueryValue(handle:key_h, item:"TEMP");
RegCloseKey(handle:key_h);
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

if ( isnull(value) )
{
 NetUseDel();
 exit(1);
}

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:value[1]);
rootfile =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\sqlsp.log", string:value[1]);


r = NetUseAdd(login:kb_smb_login(), password:kb_smb_password(), domain:kb_smb_domain(), share:share);
if ( r != 1 ) exit(1);

handle =  CreateFile (file:rootfile, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

 if ( ! isnull(handle) )
 {
  CloseFile(handle:handle);
 {
 set_kb_item(name:"SMB/Missing/MS00-035", value:TRUE);
 hotfix_security_warning();
 }
 }

NetUseDel();
