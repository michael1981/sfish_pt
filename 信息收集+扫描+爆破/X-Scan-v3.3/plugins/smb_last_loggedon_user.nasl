#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(38689);
  script_version("$Revision: 1.1 $");
  
  script_name(english:"SMB Last Logged On User");
  script_summary(english:"Checks the last logged on user");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to identify the last logged on user on the remote
system." );
 script_set_attribute(attribute:"description", value:
"By connecting to the remote host with the supplied credentials, this
plugin identifies the username associated with the last successful
logon." );
 script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/kb/260324" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"risk_factor", value:"None" );

 script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("smb_enum_services.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");

if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);

# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();
if (!get_port_state(port)) exit(0);
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

soc = open_sock_tcp(port);
if (!soc) exit(0);

session_init(socket:soc, hostname:name);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) {
  NetUseDel();
  exit(0);
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}

username = NULL;

key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"DefaultUserName");
  if (!isnull(value)) username = value[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
NetUseDel();


if(!isnull(username))
{
 report = NULL;  
 report = string("\n",
            "Last Successful logon : ", username, "\n"); 
  security_note(port:port,extra:report);
}
