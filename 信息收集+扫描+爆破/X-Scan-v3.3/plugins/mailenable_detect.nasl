#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(23753);
  script_version("$Revision: 1.6 $");

  script_name(english:"MailEnable Detection");
  script_summary(english:"Checks for MailEnable");

 script_set_attribute(attribute:"synopsis", value:
"There is a mail server installed on the remote Windows host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running MailEnable, a commercial mail server for
Windows." );
 script_set_attribute(attribute:"see_also", value:"http://www.mailenable.com/" );
 script_set_attribute(attribute:"solution", value:
"Make sure that this is a legitimate mail server." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");


# Connect to the appropriate share.
if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);
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
if (rc != 1)
{
  NetUseDel();
  exit(0);
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0, "cannot connect to the remote registry");
}


# Determine location of MailEnable install and some info about it.
path_main = NULL;
path_bin = NULL;
prod = NULL;
ver = NULL;

key = "SOFTWARE\Mail Enable\Mail Enable";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[0]; ++i) {
    value = RegEnumValue(handle:key_h, index:i);
    if (!isnull(value))
    {
      subkey = value[1];
      if (strlen(subkey) && subkey =~ "(Professional|Enterprise) Version$")
      {
        prod = ereg_replace(pattern:"^(.+) Version", replace:"\1", string:subkey);
        item = RegQueryValue(handle:key_h, item:subkey);
        if (!isnull(item)) ver = item[1];
      }
    }
  }
  if (isnull(prod))
  {
    prod = "Standard";
    item = RegQueryValue(handle:key_h, item:"Version");
    if (!isnull(item)) ver = item[1];

  }

  item = RegQueryValue(handle:key_h, item:"Data Directory");
  if (!isnull(item)) path_main = item[1];

  item = RegQueryValue(handle:key_h, item:"Application Directory");
  if (!isnull(item)) path_bin = item[1];

  RegCloseKey(handle:key_h);
}
if (isnull(prod) || isnull(ver) || isnull(path_main) || isnull(path_bin))
{
  NetUseDel();
  exit(0);
}


# Extract info about any hotfixes that have been installed.
hotfixes = "";

key = "SOFTWARE\Mail Enable\Mail Enable\Updates";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    if (strlen(subkey) && subkey =~ "^ME-[0-9]+$")
    {
      key2 = key + "\" + subkey;
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        item = RegQueryValue(handle:key2_h, item:"Status");
        if (!isnull(item) && item[1] > 0) hotfixes += subkey + ' & ';

        RegCloseKey(handle:key2_h);
      }
    }
  }
  RegCloseKey (handle:key_h);
}

RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);


kb_base = "SMB/MailEnable/" + prod;


# Grab version of each service binary.
services = make_list(
  "MESMTPC", 
  "MEHTTPS",
  "MEPOPS", 
  "MEIMAPS",
  "MERADMS"
);
foreach service (services)
{
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path_bin);
  exe = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\"+service+".exe", string:path_bin);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(0);
  }

  fh = CreateFile(
    file:exe,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (!isnull(fh))
  {
    ver2 = GetFileVersion(handle:fh);
    CloseFile(handle:fh);

    # Save version in a KB entry.
    if (!isnull(ver2))
    {
      version = string(ver2[0], ".", ver2[1], ".", ver2[2], ".", ver2[3]);
      save_version_in_kb(key:kb_base+"/"+service+"/Version", ver:version);
    }
  }
}
NetUseDel();


# Update KB and report findings.
set_kb_item(name:"SMB/MailEnable/Installed", value:TRUE);
set_kb_item(name:kb_base, value:TRUE);
set_kb_item(name:kb_base+"/Version", value:ver);
set_kb_item(name:kb_base+"/Path", value:path_main);
if (hotfixes)
{
  hotfixes = substr(hotfixes, 0, strlen(hotfixes)-1-3);
  set_kb_item(name:kb_base+"/Hotfixes", value:hotfixes);
}

if (report_verbosity)
{
  report = string(
    "\n",
    "  Product  : ", prod, " Edition\n",
    "  Path     : ", path_main, "\n",
    "  Version  : ", ver, "\n"
  );
  if (hotfixes)
  {
    report = string(
      report,
      "  Hotfixes : ", hotfixes, "\n"
    );
  }
  security_note(port:port, extra:report);
}
else security_note(port);
