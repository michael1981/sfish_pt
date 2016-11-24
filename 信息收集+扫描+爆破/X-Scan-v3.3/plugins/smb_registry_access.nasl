#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10400);
 script_version ("$Revision: 1.38 $");
 
 name["english"] = "SMB accessible registry";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Access the remote Windows Registry." );
 script_set_attribute(attribute:"description", value:
"It was possible to access the remote Windows Registry using the login
/ password combination used for the Windows local checks (SMB tests)." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_end_attributes();

 
 summary["english"] = "Determines whether the remote registry is accessible";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl", "start_registry_svc.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password");
 script_exclude_keys("SMB/samba");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");

if (get_kb_item("SMB/samba")) exit(0);


port = kb_smb_transport();
if(!port)port = 139;

name	= kb_smb_name(); 	if(!name)exit(0);
login	= kb_smb_login(); 
pass	= kb_smb_password(); 	
domain  = kb_smb_domain(); 	
port	= kb_smb_transport();

if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

logged = 0;

session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r == 1 )
{
 hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
 if (! isnull(hklm) ) 
 {
  key_h = RegOpenKey(handle:hklm, key:"SYSTEM\CurrentControlSet\Control\Session Manager\Environment", mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
   item = RegQueryValue(handle:key_h, item:"PROCESSOR_ARCHITECTURE");
   if (!isnull(item))
   {
    arch = item[1];
    if ("x86" >!< arch)
      set_kb_item(name:"SMB/WoW", value:TRUE);
   }

   RegCloseKey(handle:key_h);
  }

  RegCloseKey (handle:hklm);
  logged = 1;
 }
 NetUseDel();
}

if (logged == 0)
{
 set_kb_item(name:"SMB/registry_not_accessible", value:TRUE);
}
else
{
 security_note (port);

 set_kb_item(name:"SMB/registry_access", value:TRUE);
}
