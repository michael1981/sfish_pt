#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10456);
 script_version ("$Revision: 1.32 $");
 
 script_name(english:"SMB Service Enumeration");
 script_set_attribute(attribute:"synopsis", value:
"It is possible to enumerate remote services." );
 script_set_attribute(attribute:"description", value:
"This plugin implements the SvcOpenSCManager() and SvcEnumServices()
calls to obtain, using the SMB protocol, the list of active and
inactive services of the remote host.

An attacker may use this feature to gain better knowledge of the remote
host." );
 script_set_attribute(attribute:"solution", value:
"To prevent the listing of the services for being obtained, you should
either have tight login restrictions, so that only trusted users can 
access your host, and/or you should filter incoming traffic to this port." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N" );


script_end_attributes();

 script_summary(english:"Enumerates the list of remote services");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("netbios_name_get.nasl", "smb_login.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");


port = kb_smb_transport();
if(!port)port = 139;


# Does not work against Samba
smb = get_kb_item("SMB/samba");
if(smb)exit(0);


name = kb_smb_name();
if(!name)return(FALSE);

if(!get_port_state(port))return(FALSE);

login = kb_smb_login();
pass  = kb_smb_password();

if(!login)login = "";
if(!pass) pass = "";

dom = kb_smb_domain();

	  
soc = open_sock_tcp(port);
if(!soc)exit(0);

session_init (socket:soc,hostname:name);
ret = NetUseAdd (login:login, password:pass, domain:dom, share:"IPC$");
if (ret != 1)
{
 close (soc);
 exit (0);
}


handle = OpenSCManager (access_mode:SC_MANAGER_ENUMERATE_SERVICE);
if (isnull (handle))
{
 NetUseDel();
 exit (0);
}

active_list = EnumServicesStatus (handle:handle, type:SERVICE_WIN32, state:SERVICE_ACTIVE);
inactive_list = EnumServicesStatus (handle:handle, type:SERVICE_WIN32, state:SERVICE_INACTIVE);

CloseServiceHandle (handle:handle);
NetUseDel ();

if (isnull (active_list) && isnull(inactive_list))
  exit (1, "No services were detected.");

services = NULL;
active_services = NULL;
inactive_services = NULL;

foreach elem (active_list)
{
 parse = GetService (service:elem);
 active_services += parse[1] + " [ " + parse[0] + ' ] \n';
 set_kb_item(name:"SMB/svc/" + parse[0], value:SERVICE_ACTIVE);
}

if (max_index(active_list) > 0)
{
 services += '\nActive Services :\n\n' + active_services;
 set_kb_item(name:"SMB/svcs", value:active_services);
}

foreach elem (inactive_list)
{
 parse = GetService (service:elem);
 inactive_services += parse[1] + " [ " + parse[0] + ' ] \n';
 set_kb_item(name:"SMB/svc/" + parse[0], value:SERVICE_INACTIVE);
}

if (max_index(inactive_list) > 0)
{
 services += '\nInactive Services :\n\n' + inactive_services;
 set_kb_item(name:"SMB/svcs/inactive", value:inactive_services);
}

if(services)
 security_note(extra: services, port:port);
