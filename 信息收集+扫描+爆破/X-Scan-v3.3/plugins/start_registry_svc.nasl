#
# (C) Tenable Network Security, Inc.
#

# @PREFERENCES@

include("compat.inc");

if(description)
{
 script_id(35703);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "SMB Registry : Start the Registry Service during the scan";
 script_name(english:name["english"]);
 
  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The registry service was enabled for the duration of the scan."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
	"To perform a full credentialed scan, Nessus needs the ability to connect to\n",
	"the remote registry service (RemoteRegistry). If the service is down, this\n",
	"plugin will attempt to start for the duration of the scan\n\n",
	"You need to explicitely set the option 'Start the Registry Service', \n",
	"'Advanced->Start the Registry' for this plugin to work.\n"
    )
  );
  script_set_attribute(
    attribute:"solution",
    value:"N/A"
  );
  script_set_attribute(
    attribute:"risk_factor", 
    value:"None"
  );
  script_end_attributes();

 
 script_summary(english:"Determines whether the remote registry service is running");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc");
 script_family(english:"Settings");
 script_dependencies("netbios_name_get.nasl", "smb_login.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password");
 script_exclude_keys("SMB/samba");
 script_add_preference(name:"Start the registry service during the scan", type:"checkbox", value:"no");
 script_require_ports(139, 445);
 exit(0);
}

include("global_settings.inc");
include("smb_func.inc");

if (get_kb_item("SMB/samba")) exit(0);

opt = script_get_preference("Start the registry service during the scan");
if ( opt != "yes" ) exit(0);


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
  handle = OpenSCManager (access_mode:SC_MANAGER_ALL_ACCESS);
  if ( !isnull(handle) )
  {
     shandle = OpenService (handle:handle, service:"RemoteRegistry", access_mode:MAXIMUM_ALLOWED);
     if ( !isnull(handle) )
     {
       status = QueryServiceStatus (handle:shandle);
       if ( ! isnull(status) )
	{
	if ( status[1] == SERVICE_STOPPED )
         {
 	   ret = StartService (handle:shandle);
	   if ( ret == 1 ) 
		{
		security_note(port:0, extra:"The registry service was successfully started for the duration of the scan");
	   	set_kb_item(name:"SMB/shutdown_registry_after_scan", value:TRUE);
		}
         } 
	}
	 else err = "Could not query the service status";
        CloseServiceHandle (handle:shandle);
     } else err = "Could not open RemoteRegistry";
   CloseServiceHandle (handle:handle);
  } else err = "OpenSCManager() failed";
 NetUseDel();
}
else err = "NetUseAdd failed";

if ( strlen(err) )
{
 set_kb_item(name:"SMB/start_registry/failed", value:err);
}
