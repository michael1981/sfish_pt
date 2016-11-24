#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40619);
  script_version("$Revision: 1.1 $");

  script_name(english:"Subversion Client/Server Detection (Windows)");
  script_summary(english:"Checks if Subversion Client/Server is installed"); 
 
  script_set_attribute(attribute:"synopsis", value:
"Version control software is installed on the remote host." );

  script_set_attribute(attribute:"description", value:
"Subversion, an open source version control system, is installed on
the remote system.  Subversion can be installed on Windows using
CollabNet-certified binaries or through third-party packages such as
VisualSVN, TortoiseSVN and SlikSVN.  Third-party packages typically
include CollabNet binaries in thier respective packages, and it is not
uncommon to have more than one Subversion package installed on a given
system. 
 
This plugin tries to identify the versions of Subversion client or
server included with popular Subversion packages." );

   script_set_attribute(attribute:"solution", value:"n/a" );

  script_set_attribute(attribute:"see_also", value:"http://subversion.tigris.org/" );
  script_set_attribute(attribute:"risk_factor", value:"None" );

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

if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "The 'SMB/Registry/Enumerated' KB item is missing.");

name    =  kb_smb_name();
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if (!get_port_state(port)) exit(1,"Port is not open.");

soc = open_sock_tcp(port);
if (!soc) exit(1, "Could not open socket to SMB port.");

session_init(socket:soc, hostname:name);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to IPC$ share.");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Can't connect to remote registry.");
}

# Figure out if Subversion is installed.
# We use this later to make a guess if subversion
# is installed.

subversion_installed = 0;

list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (!isnull(list))
{
  foreach name (keys(list))
  {
    prod = list[name];
    if (prod && "Subversion" >< prod)
    {
     subversion_installed = 1;
     break;
    }
  }
}

paths = make_array();

key = "SOFTWARE\CollabNet\Subversion";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i)
  {
   # Try to be locale independent.
    subkey = RegEnumKey(handle:key_h, index:i);
    if (strlen(subkey) && subkey =~ "^[0-9.]+$")
    {   
      key2 = key + "\" + subkey + "\Server";
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        value = RegQueryValue(handle:key2_h, item:"Install Location");
        if (!isnull(value)) paths["CollabNet"]= value[1];

        RegCloseKey(handle:key2_h);
      }
    }
  }
  RegCloseKey (handle:key_h);
}

# Search for VisualSVN

key = "SOFTWARE\VisualSVN\VisualSVN Server";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"InstallDir");
  if (!isnull(value)) 
  {
    path = value[1];
    if(!ereg(pattern:"\\$",string:path)) 
      paths["VisualSVN"] = path + "\bin";
    else 
      paths["VisualSVN"] = path + "bin";
  } 
  RegCloseKey(handle:key_h);
}

# Search for SlikSVN
  
key = "SOFTWARE\SlikSvn\Install";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"Location");
  if (!isnull(value)) paths["SlikSVN"] = value[1];

  RegCloseKey(handle:key_h);
}

# Search for TortoiseSVN client

key = "SOFTWARE\TortoiseSVN";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"ProcPath");
  if (!isnull(value)) paths["TortoiseSVN"] = value[1];

  RegCloseKey(handle:key_h);
}

# Make a guess for Tigris installs

if(subversion_installed)
{
 path = hotfix_get_programfilesdir() + "\Subversion\bin";
 paths["Tigris"] = path;
}

RegCloseKey(handle:hklm);

info = NULL;

foreach prod (keys(paths))
{
  exe_client = NULL;
  exe_svr = NULL; 
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:paths[prod]);

  if("TortoiseSVN" >< prod)
  {
    exe_client =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:paths[prod]);
    paths[prod] = str_replace(find:"\TortoiseProc.exe",replace:"",string:paths[prod]);
  }
  else
  {
    exe_client =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\svn.exe", string:paths[prod]);
    exe_svr    = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\svnserve.exe", string:paths[prod]);
  }

  NetUseDel(close:FALSE);
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(1, "Can't connect to '" + share + "' share.") ;
  }

  fh = CreateFile(file:exe_client, 
	desired_access:GENERIC_READ, 
	file_attributes:FILE_ATTRIBUTE_NORMAL, 
	share_mode:FILE_SHARE_READ, 
	create_disposition:OPEN_EXISTING);

  client_ver = NULL;

  if (!isnull(fh))
  {
    client_ver = GetFileVersion(handle:fh);
    CloseFile(handle:fh);

    if (!isnull(client_ver))
    {
      version = string(client_ver[0], ".", client_ver[1], ".", client_ver[2]);
      set_kb_item(name:"SMB/Subversion/Client/"+ prod + "/"+ version, value:paths[prod]);
      info += '  Application   : Subversion Client \n' +
              '  Path          : ' + paths[prod]+ '\n' +
              '  Version       : ' + version + '\n' +
              '  Packaged with : ' + prod + '\n' +
              '\n';
    }
  }

  server_ver = NULL;

  # Don't look for SVN Server for TortoiseSVN
  if(!isnull(exe_svr))
  {
    fh = CreateFile(file:exe_svr,
         desired_access:GENERIC_READ,
         file_attributes:FILE_ATTRIBUTE_NORMAL,
         share_mode:FILE_SHARE_READ,
         create_disposition:OPEN_EXISTING);

    if (!isnull(fh))
    {
      server_ver = GetFileVersion(handle:fh);
      CloseFile(handle:fh);
  
      if (!isnull(server_ver))
      {
        version = string(server_ver[0], ".", server_ver[1], ".", server_ver[2]);
        set_kb_item(name:"SMB/Subversion/Server/"+ prod + "/" + version, value:paths[prod]);
        info += '  Application   : Subversion Server \n' +
            '  Path          : ' + paths[prod] + '\n' +
            '  Version       : ' + version + '\n' +
            '  Packaged with : ' + prod + '\n' +
            '\n';
      }
    }
  }
}

NetUseDel();

if(!isnull(info))
{
  set_kb_item(name:"SMB/Subversion/Installed", value:TRUE);

  if (report_verbosity > 0)
  { 
    if (max_index(split(info)) > 1) s = "s of Subversion are";
    else s = " of Subversion is";
    
    report = string(
      "\n",
      "The following instance", s, " installed :\n",
      "\n",
      info
    );
    security_note(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_note(get_kb_item("SMB/transport"));
}
