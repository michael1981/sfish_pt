#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(33545);
  script_version("$Revision: 1.6 $");

  script_name(english:"Sun Java Runtime Environment Detection");
  script_summary(english:"Checks for Sun JRE installs");
 
 script_set_attribute(attribute:"synopsis", value:
"There is a Java runtime environment installed on the remote Windows
host." );
 script_set_attribute(attribute:"description", value:
"One or more instances of Sun's Java Runtime Environment (JRE) is
installed on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://java.sun.com/" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
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


# Identify possible installs.
java_homes = make_array();
runtimes = make_array();

key = "SOFTWARE\JavaSoft\Java Runtime Environment";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    if (strlen(subkey) && subkey =~ "^[0-9]+\.[0-9]+\.[0-9]+_[0-9]+$")
    {
      key2 = key + "\" + subkey;
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        item = RegQueryValue(handle:key2_h, item:"JavaHome");
        if (!isnull(item))
        {
          path = item[1];
          java_homes[subkey] = path;
        }

        item = RegQueryValue(handle:key2_h, item:"RuntimeLib");
        if (!isnull(item))
        {
          file = item[1];
          runtimes[subkey] = file;
        }
        RegCloseKey(handle:key2_h);
      }
    }
  }
  RegCloseKey (handle:key_h);
}

RegCloseKey(handle:hklm);
if (isnull(runtimes))
{
  NetUseDel();
  exit(0);
}


# Verify each install and generate a report.
info = "";

foreach version (sort(keys(runtimes)))
{
  file = runtimes[version];
  if (java_home[version]) path = java_home[version];
  else
  {
    path = file;
    if ("\bin\client\jvm.dll" >< path) path = path - "\bin\client\jvm.dll";
  }

  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:file);
  file2 = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:file);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(0);
  }

  fh = CreateFile(
    file:file2,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (!isnull(fh))
  {
    # All we're interested in is whether the runtime exists.
    set_kb_item(name:"SMB/Java/JRE/"+version, value:path);

    info += '\n' +
            '  Path    : ' + path + '\n' +
            '  Version : ' + version + '\n';

    CloseFile(handle:fh);
  }
  NetUseDel(close:FALSE);
}
NetUseDel();


# Report what we found.
if (info)
{
  set_kb_item(name:"SMB/Java/JRE/Installed", value:TRUE);

  if (report_verbosity > 0)
  {
    if (max_index(split(info)) > 3) s = "s of Sun's JRE are";
    else s = " of Sun's JRE is";

    report = string(
      "\n",
      "The following instance", s, " installed on the remote\n",
      "host :\n",
      info
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
