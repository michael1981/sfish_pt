#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20843);
  script_version("$Revision: 1.12 $");

  script_name(english:"BitTorrent Detection");
  script_summary(english:"Checks for BitTorrent"); 
 
 script_set_attribute(attribute:"synopsis", value:
"There is a peer-to-peer file sharing application installed on the remote
host." );
 script_set_attribute(attribute:"description", value:
"BitTorrent is installed on the remote Windows host.  BitTorrent is an
open-source peer-to-peer file sharing application." );
 script_set_attribute(attribute:"see_also", value:"http://www.bittorrent.com/" );
 script_set_attribute(attribute:"solution", value:
"Remove this software if its use does not match your corporate security
policy." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("smb_func.inc");


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


# Determine if it's installed.
path = NULL;

key = "SOFTWARE\BitTorrent\Plugin";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"rootpath");
  if (!isnull(value)) path = value[1];
  RegCloseKey(handle:key_h);
}
if (isnull(path))
{
  key = "SOFTWARE\Classes\Applications\bittorrent.exe\shell\open\command";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(value))
    {
      # nb: the exe itself appears in quotes.
      exe = ereg_replace(pattern:'^"([^"]+)".*', replace:"\1", string:value[1]);
      path = ereg_replace(pattern:"^(.+)\\[^\\]+$", replace:"\1", string:exe);
    }
    RegCloseKey(handle:key_h);
  }
}
if (isnull(path)) 
{
  key = "SOFTWARE\Classes\bittorrent\shell\open\command";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(value) && "bittorrent.exe" >< tolower(value[1]))
    {
      # nb: the exe itself appears in quotes.
      exe = ereg_replace(pattern:'^"([^"]+)".*', replace:"\1", string:value[1]);
      path = ereg_replace(pattern:"^(.+)\\[^\\]+$", replace:"\1", string:exe);
    }
    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);


# If it is...
if (path) 
{
  # Locate BitTorrent's library.zip.
  #
  # nb: this doesn't exist in newer versions of BitTorrent (eg, 6.0).
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  zip =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\library.zip", string:path);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(0, "cannot connect to the remote share");
  }

  fh = CreateFile(
    file:zip,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );

  ver = NULL;
  if (!isnull(fh))
  {
    # Find start / size of zip file's central directory.
    # 
    # nb: see <http://www.pkware.com/documents/casestudies/APPNOTE.TXT>.
    set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);
    fsize = GetFileSize(handle:fh);
    chunk = 200;                       # arbitrary, but works pretty well
    if (fsize > chunk)
    {
      data = ReadFile(handle:fh, length:chunk, offset:fsize-chunk);
      if (data)
      {
        eocdr = strstr(data, raw_string(0x50, 0x4b, 0x05, 0x06));
        if (eocdr && strlen(eocdr) > 20) {
          dir_size = getdword(blob:eocdr, pos:12);
          dir_ofs = getdword(blob:eocdr, pos:16);
        }
      }
    }

    # Find start of __init__.pyc from zip file's central directory.
    if (dir_ofs && dir_size)
    {
      data = ReadFile(handle:fh, length:dir_size, offset:dir_ofs);
      if (data)
      {
        fname = stridx(data, "BitTorrent/__init__.pycPK");
        if (fname >= 0) ofs = getdword(blob:data, pos:fname-4);
      }
    }

    # Locate the contents of __init__.pyc within the zip file.
    if (ofs)
    {
      data = ReadFile(handle:fh, length:1024, offset:ofs);
      if (data)
      {
        # Pull version out from a Python string.
        blob = strstr(data, "BitTorrents");
        if (blob)
        {
          blob = blob - "BitTorrents";
          length = getdword(blob:blob, pos:0);
          if (length) ver = substr(blob, 4, 4-1+length);
        }
      }
    }
    CloseFile(handle:fh);
  }

  # Report findings.
  set_kb_item(name:"SMB/BitTorrent/installed", value:TRUE);
  set_kb_item(name:"SMB/BitTorrent/Path", value:path);

  if (isnull(ver))
  {
    info = "An unknown version of BitTorrent is installed under :";
  }
  else
  {
    set_kb_item(name:"SMB/BitTorrent/Version", value:ver);

    info = "Version " + ver + " of BitTorrent is installed under :";
  }

  report = string(
    "\n",
    info, "\n",
    "\n",
    "  ", path, "\n"
  );
  security_note(port:port, extra:report);
}


# Clean up.
NetUseDel();
