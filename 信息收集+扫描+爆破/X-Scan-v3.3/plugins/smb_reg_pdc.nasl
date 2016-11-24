#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10413);
 script_version ("$Revision: 1.19 $");

 name["english"] = "SMB Registry : is the remote host a PDC/BDC";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote system is a Domain Controller." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be a Primary Domain Controller or a Backup
Domain Controller. 

This can be verified by the value of the registry key 'ProductType'
under 'HKLM\SYSTEM\CurrentControlSet\Control\ProductOptions'." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
script_end_attributes();

 
 summary["english"] = "Determines if the remote host is a PDC/BDC";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl", "smb_registry_access.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");
 script_require_ports(139, 445);
 exit(0);
}

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


key = "SYSTEM\CurrentControlSet\Control\ProductOptions";
item = "ProductType";

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
 value = RegQueryValue(handle:key_h, item:item);
 if (!isnull (value) && (value[1] == "LanmanNT"))
   security_note (port);
 
 RegCloseKey (handle:key_h);
}

RegCloseKey (handle:hklm);
NetUseDel ();
