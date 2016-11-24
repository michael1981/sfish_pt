#
# (C) Tenable Network Security, Inc.
#
# Thanks to Greg Hoglund <hoglund@hbgary.com> for suggesting this.
#


include("compat.inc");

if(description)
{
 script_id(12028);
 script_version ("$Revision: 1.8 $");
 
 name["english"] = "WindowsUpdate disabled";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Remote system is not configured for automatic updates." );
 script_set_attribute(attribute:"description", value:
"The remote host does not have Windows Update enabled. 

Enabling WindowsUpdate will ensure that the remote Windows host has
all the latest Microsoft Patches installed." );
 script_set_attribute(attribute:"solution", value:
"Enable Windows Update on this host" );
 script_set_attribute(attribute:"see_also", value:"http://www.microsoft.com/security/protect/" );
 script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/kb/328010" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
script_end_attributes();

 
 summary["english"] = "Determines the value of AUState";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl", "smb_registry_access.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");
 script_require_ports(139, 445);
 exit(0);
}

include("global_settings.inc");
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

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update";
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update";

austate = NULL;
auoptions = NULL;
info = NULL;

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
  value = RegQueryValue(handle:key_h, item:"AUState");
  if (!isnull (value) && value[1] == 7) 
  { 
    austate = value[1];
    info +=  string("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\AUState : ",austate,"\n");
  } 

  value = RegQueryValue(handle:key_h, item:"AUOptions");
  if (!isnull (value) && value[1] == 1)
  {
    auoptions = value[1];
    info +=  string("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\AUOptions : ",auoptions,"\n");
  }
 
 RegCloseKey (handle:key_h);
}

RegCloseKey (handle:hklm);
NetUseDel ();

if(!isnull(info))
{
  if(report_verbosity > 0)
  {
   report = string("\n",
     "Nessus determined 'Automatic Updates' are disabled based","\n",
     "on the following registry setting(s) :","\n\n",
     info);
    security_note(port:port,extra:report);
  }
  else 
    security_note(port);
}

