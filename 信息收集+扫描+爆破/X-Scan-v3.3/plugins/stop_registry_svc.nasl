#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(35704);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "SMB Registry : Stop the Registry Service after the scan";
 script_name(english:name["english"]);
 
  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The registry service was stopped after the scan."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
	"To perform a full credentialed scan, Nessus needs the ability to connect to\n",
	"the remote registry service (RemoteRegistry). If the service is down and if\n",
	"Nessus automatically enabled the registry for the duration of the scan,\n",
	"this plugins will stop it afterwards."
    )
  );
  script_set_attribute(
    attribute:"risk_factor", 
    value:"None"
  );
  if ( NASL_LEVEL >= 4000 ) script_set_attribute(attribute:"always_run", value:TRUE);
  script_end_attributes();

 
 
 summary["english"] = "Determines whether the remote registry service was started by nessusd";
 script_summary(english:summary["english"]);
 
 script_category(ACT_END);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc");
 family["english"] = "Settings";
 script_family(english:family["english"]);
 
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password", "SMB/shutdown_registry_after_scan");
 script_require_ports(139, 445);
 script_exclude_keys("Host/dead");
 exit(0);
}

include("smb_func.inc");

if (!get_kb_item("SMB/shutdown_registry_after_scan")) exit(0);
if ( get_kb_item("Host/dead") ) exit(0);

port = kb_smb_transport();
if(!port)port = 139;

name	= kb_smb_name(); 	if(!name)exit(0);
login	= kb_smb_login(); 
pass	= kb_smb_password(); 	
domain  = kb_smb_domain(); 	
port	= kb_smb_transport();

soc = open_sock_tcp(port);
if ( ! soc ) {
  set_kb_item(name:"SMB/stop_registry/failed", value:"Could not connect to port " + port);
  exit(0);
}

logged = 0;

session_init(socket:soc, hostname:name);
err = NULL;
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
       if ( ! isnull(status) && status[1] == SERVICE_RUNNING )
        {
 	   ret = ControlService(handle:shandle, control:SERVICE_CONTROL_STOP);
	   if ( ret == 1 ) 
		{
		security_note(port:0, extra:"The registry service was successfully stopped after the scan");
		}
	   else err = "StopService() failed";
        }
        CloseServiceHandle (handle:shandle);
     }
     else err = "OpenService() failed";
   CloseServiceHandle (handle:handle);
  }
  else err = "OpenSCManager() failed";
 NetUseDel();
}
else err = "Could not connect to IPC$";

if ( strlen(err) ) set_kb_item(name:"SMB/stop_registry/failed", value:err);
