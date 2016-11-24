#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if (description)
{
  script_id(42399);
  script_version("$Revision: 1.1 $");

  script_name(english:"Microsoft Silverlight Detection");
  script_summary(english:"Checks for Microsoft Silverlight");

  script_set_attribute(
    attribute:'synopsis',
    value:"The remote host has Microsoft Silverlight installed."
  );
  script_set_attribute(
    attribute:'description',
    value:
"A version of Microsoft's Silverlight is installed on this host.

Microsoft Silverlight is a web application framework that provides
functionalities similar to those in Adobe Flash, integrating
multimedia, graphics, animations and interactivity into a single
runtime environment."
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://silverlight.net/'
  );

  script_set_attribute(
    attribute:'solution',
    value:'n/a'
  );

  script_set_attribute(
      attribute:'risk_factor',
      value:'None'
  );

  script_set_attribute( attribute:'plugin_publication_date', value:'2009/11/05' );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");

# Connect to the appropriate share.
if (!get_kb_item('SMB/Registry/Enumerated'))
  exit( 1, "The 'SMB/Registry/Enumerated' KB item is missing.");

name    =  kb_smb_name();
port    =  kb_smb_transport();

if (!get_port_state(port))
  exit(1, "Port "+port+" is not open.");
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

soc = open_sock_tcp(port);
if (!soc)
  exit(1, "Can't open socket on port "+port+".");

session_init(socket:soc, hostname:name);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to IPC$ share.");
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Can't connect to remote registry.");
}

reg_key = 'SOFTWARE\\Microsoft\\Silverlight';
reg_val = 'version';

key_h = RegOpenKey(handle:hklm, key:reg_key, mode:MAXIMUM_ALLOWED);

value = NULL;
if ( !isnull(key_h) )
{
  value = RegQueryValue( handle:key_h, item:reg_val );
  RegCloseKey (handle:key_h);
}
RegCloseKey(handle:hklm);
if ( isnull( value ) )
{
  NetUseDel();
  exit(1, "Microsoft Silverlight not detected.");
}

NetUseDel(close:FALSE);
value   = value[ 1 ];
val_arr = split( value, sep:'.', keep:FALSE );

path = hotfix_get_programfilesdirx86();
if ( !path )
  path = hotfix_get_programfilesdir();
if ( !path )
{
  NetUseDel();
  exit( 1,'Could not determine Program Files Directory.' );
}

# Determine its version from the executable itself.
share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:'\\1$', string:path);
path += '\\Microsoft Silverlight\\';
if ( int( val_arr[ 0 ] ) > 1 )
  path +=  value  ;

dll =  ereg_replace( pattern:'^[A-Za-z]:(.*)', replace:'\\1\\npctrl.dll', string:path );

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to '"+share+"' share.");
}

fh = CreateFile(
  file:dll,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

if ( !fh )
{
  NetUseDel();
  exit( 1,'Could not find Silverlight\'s npctrl.dll file.' );
}
CloseFile(handle:fh);
NetUseDel();

set_kb_item(name:"SMB/Silverlight/Path", value:path);
set_kb_item(name:"SMB/Silverlight/Version", value:value);

if (report_verbosity > 0)
{
  report = string(
    "\n",
    "  Product : Microsoft Silverlight\n",
    "  Path    : ", path, "\n",
    "  Version : ", value, "\n"
  );

  security_note( port:port, extra:report );
}
else security_note(port);
