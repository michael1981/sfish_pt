#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10431);
 script_version ("$Revision: 1.21 $");
 
 name["english"] = "SMB Registry : missing winreg";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Everyone can access the remote registry." );
 script_set_attribute(attribute:"description", value:
"The registry key HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg
is missing.

This key allows you to define what can be viewed in the registry by 
non administrators." );
 script_set_attribute(attribute:"solution", value:
"install service pack 3 if not done already, and create and create
SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths
Under this key, create the value 'Machine' as a REG_MULTI_SZ and 
put in it what you allow to be browsed remotely." );
 script_set_attribute(attribute:"see_also", value:"http://www.microsoft.com/technet/prodtechnol/winntas/maintain/mngntreg/admreg.asp" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P" );
 script_end_attributes();
 
 summary["english"] = "Determines if the winreg key is present";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl", "smb_registry_full_access.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password","SMB/registry_full_access");
 script_exclude_keys("SMB/Win2K/ServicePack");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");

access = get_kb_item("SMB/registry_access");
if(!access)exit(0);

version = get_kb_item("SMB/WindowsVersion");
if(!version)exit(0);
# false positive on win2k - they must protect it or something - mss
if(egrep(pattern:"^5.",string:version))exit(0);


#---------------------------------------------------------------------#
# Here is our main()                                                  #
#---------------------------------------------------------------------#

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

key = "SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths";
item = "Machine";

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
 value = RegQueryValue(handle:key_h, item:item);
 if (!isnull (value))
  security_warning(port);

 RegCloseKey (handle:key_h);
}

RegCloseKey (handle:hklm);
NetUseDel ();
