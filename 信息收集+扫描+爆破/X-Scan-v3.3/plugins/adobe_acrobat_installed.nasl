#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if (description)
{
  script_id(40797);
  script_version("$Revision: 1.2 $");

  script_name(english:"Adobe Acrobat Detection");
  script_summary(english:"Checks for Adobe Acrobat");

  script_set_attribute(
    attribute:'synopsis',
    value:string(
      'Adobe Corporation\'s Acrobat software is installed on the remote\n',
      'Windows host.'
    )
  );

  script_set_attribute(
    attribute:'description',
    value:string(
      'A version of Adobe Corporation\'s Acrobat software, a PDF file creation\n',
      'and editing tool, is installed on the remote Windows host.'
    )
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://www.adobe.com/products/acrobat/'
  );

  script_set_attribute(
    attribute:'solution',
    value:'n/a'
  );

  script_set_attribute(
      attribute:'risk_factor',
      value:'None'
  );

  script_set_attribute( attribute:'plugin_publication_date', value:'2009/08/28' );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("smb_func.inc");

# Connect to the appropriate share.
if (!get_kb_item('SMB/Registry/Enumerated'))
  exit( 1, "The 'SMB/Registry/Enumerated' KB item is missing.");
name    =  kb_smb_name();
port    =  kb_smb_transport();
if (!get_port_state(port))
  exit(1, string( 'Failed port state on : ', port ) );
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

soc = open_sock_tcp(port);
if (!soc)
  exit(1, string( 'Could not open socket to port : ', port ) );

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

# Determine where it's installed.
path = NULL;
min = NULL;
max = NULL;

# - nb: this works for recent versions of Adobe Acrobat.
key = 'SOFTWARE\\Adobe\\Adobe Acrobat';
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    if (strlen(subkey) && subkey =~ "^[0-9.]+$")
    {
      key2 = key + '\\' + subkey + '\\Installer';
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        value = RegQueryValue(handle:key2_h, item:"VersionMax");
        if (!isnull(value)) max = int(value[1]);

        value = RegQueryValue(handle:key2_h, item:"VersionMin");
        if (!isnull(value)) min = int(value[1]);

        value = RegQueryValue(handle:key2_h, item:"Path");
        if (!isnull(value)) path = ereg_replace(pattern:"^(.+)\\$", replace:'\\1', string:value[1]);

        if ( ( subkey == '8.0' ) && ( min >> 16 == 2 ) )
        {
          value = RegQueryValue(handle:key2_h, item:'VersionSU');
          if ( !isnull(value) )
          {
            su1 = value[ 1 ];
            set_kb_item(name:"SMB/Acrobat/812su1Installed", value:su1 );
          }
        }
        RegCloseKey(handle:key2_h);
      }
    }
  }
  RegCloseKey (handle:key_h);
}

RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0, 'No evidence of Acrobat found in the registry.' );
}

# Determine its version from the executable itself.
share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:'\\1$', string:path);
exe =  ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:'\\1\\Acrobat\\Acrobat.exe', string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to '"+share+"' share.");
}

fh = CreateFile(
  file:exe,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

# Grab the version number if the file was opened successfully.  Otherwise,
# bail out.
version = '';
if ( fh )
{
  version = GetProductVersion(handle:fh);
  CloseFile(handle:fh);
}
else
{
  NetUseDel();
  exit(1, "Unable to access Acrobat executable : " + exe);
}

# For some reason, the product version of acrobat.exe 7.1.0 drops back to 7.0.8.
# so check Distillr\\acrodist.exe for the product version.
if (version =~ "^7\.0\.8\.")
{
  dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:'\\1\\Distillr\\acrodist.exe', string:path);
  fh = CreateFile(
    file:dll,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  version = '';
  if ( fh )
  {
    version = GetProductVersion(handle:fh);
    CloseFile(handle:fh);
  }
  else
  {
    NetUseDel();
    exit(1, "Unable to access Acrobat executable : " + exe);
  }
}
NetUseDel();

# Save and report the version number and installation path.
if (!isnull(version) && !isnull(path))
{
  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  # Handle version changes in updates.
  if (!isnull(max) && !isnull(min))
  {
    a = (max >> 16);
    b = max & 0xffff;
    c = min >> 16;
    d = min & 0xffff;
    if (ver[0] > 7 && ver[0] == a && ver[1] == b && ver[2] < c)
    {
      ver[2] = c;
      ver[3] = d;
      version = string(ver[0], ".", ver[1], ".", ver[2]);
    }
    if (ver[0] <= 7 && a == 0 && ver[0] == b && ver[1] == c && ver[2] < d)
    {
      ver[2] = d;
      ver[3] = 0;
      version = string(ver[0], ".", ver[1], ".", ver[2]);
    }
  }

  # Reformat the version based on how it's displayed in
  # the Help, About menu pull-down.
  pat = "^([0-9]+\.[0-9]+\.[0-9])\.(2[0-9]{3})([0-9]{2})([0-9]{2})([0-9]{2})$";
  v = eregmatch(pattern:pat, string:version);
  if (!isnull(v))
  {
    if (ver[0] < 7)
    {
      version_ui = string(v[1], " ", int(v[3]), "/", int(v[4]), "/", int(v[2]));
    }
    else
    {
      version_ui = v[1];
    }
  }
  else version_ui = version;

  set_kb_item(name:"SMB/Acrobat/Path", value:path);
  set_kb_item(name:"SMB/Acrobat/Version", value:version);
  set_kb_item(name:"SMB/Acrobat/Version_UI", value:version_ui);

  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "  Product : Adobe Acrobat\n",
      "  Path    : ", path, "\n",
      "  Version : ", version_ui, "\n"
    );

    if ( su1 )
      report += '  Update  : Security Update 1 \n';

    security_note(port:port, extra:report);
  }
  else security_note(port);
}
