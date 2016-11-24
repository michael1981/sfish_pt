#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10412);
 script_version ("$Revision: 1.24 $");
 
 script_name(english:"SMB Registry : Autologon Enabled");

 script_set_attribute(attribute:"synopsis", value:
"Anyone can logon to the remote system." );
 script_set_attribute(attribute:"description", value:
"This script determines whether the autologon feature is enabled.
This feature allows an intruder to log into the remote host as 
DefaultUserName with the password DefaultPassword." );
 script_set_attribute(attribute:"solution", value:
"Delete the keys AutoAdminLogon and DefaultPassword under
HKLM\SOFTWARE\Microsoft\Window NT\CurrentVersion\Winlogon" );
 script_set_attribute(attribute:"see_also", value:"http://www.microsoft.com/windows2000/techinfo/reskit/en-us/regentry/12315.asp" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 script_summary(english:"Determines if the autologon feature is installed");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("netbios_name_get.nasl", "smb_login.nasl", "smb_registry_access.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");
 script_require_ports(139, 445);
 exit(0);
}

#

include("smb_func.inc");

port = get_kb_item("SMB/transport");
if(!port)port = 139;

name	= kb_smb_name(); 	if(!name)exit(0);
login	= kb_smb_login(); 
pass	= kb_smb_password(); 	
domain  = kb_smb_domain(); 	
port	= kb_smb_transport();

if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(0);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) ) 
{
 NetUseDel();
 exit(0);
}


key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
item1 = "DefaultUserName";
item2 = "DefaultPassword";
item3 = "AutoAdminLogon";

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
 value1 = RegQueryValue(handle:key_h, item:item1);
 value2 = RegQueryValue(handle:key_h, item:item2);
 value3 = RegQueryValue(handle:key_h, item:item3);

 if ((!isnull(value3) &&  (value3[1] != "0")) && 
     (!isnull (value1) && (value1[1] != "")) &&
      !isnull(value2) )
 {
  rep = 'Autologon is enabled on this host.\n' +
        "This allows an attacker to access it as " + value1[1] + "/" + value2[1];
  
  security_hole(port:port, extra:rep);
 }

 RegCloseKey (handle:key_h);
}

RegCloseKey (handle:hklm);
NetUseDel ();
