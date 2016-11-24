# -*- Fundamental -*-
#
# 
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# See the following licenses for details :
#  http://www.nessus.org/plugins/RegisteredFeed.pdf
#  http://www.nessus.org/plugins/DirectFeed.pdf
#  http://www.nessus.org/plugins/DirectFeedCommercial.pdf
#
#
# @NOGPL@
#
# smb_activex_func.inc
# $Revision: 1.6 $
#


ACX_NOREG   = -3;                      # No remote registry access.
ACX_NOAUTH  = -2;                      # No credentials or share does not exist.
ACX_CONNECT = -1;                      # Could not connect to port 139 or 445.
ACX_OK      =  0;                      # No error.


global_var _acx_init, _acx_hklm, _acx_soc;


#---------------------------------------------------------#
# Function    : activex_init                              #
# Description : Initialize ActiveX control access.        #
# Return      : ACX_OK if connection established;         #
#               ACX_NOAUTH if credentials were bad or     #
#                 share does not exist;                   #
#               ACX_CONNECT otherwise.                    #
#---------------------------------------------------------#
function activex_init()
{
  local_var port, rc, soc;

  port = kb_smb_transport();
  if (!get_port_state(port)) return ACX_CONNECT;

  _acx_soc = open_sock_tcp(port);
  if (!_acx_soc) return ACX_CONNECT;

  session_init(socket:_acx_soc, hostname:kb_smb_name());
  rc = NetUseAdd(
    login:kb_smb_login(), 
    password:kb_smb_password(), 
    domain:kb_smb_domain(), 
    share:"IPC$"
  );
  if (rc != 1)
  {
    NetUseDel();
    return ACX_NOAUTH;
  }

  _acx_hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
  if (isnull(_acx_hklm))
  {
    NetUseDel();
    return ACX_NOREG;
  }
  _acx_init = TRUE;
  return ACX_OK;
}


#---------------------------------------------------------#
# Function    : activex_end                               #
# Description : Close connection with remote registry.    #
# Return      : n/a                                       #
#---------------------------------------------------------#
function activex_end()
{
  if (_acx_init)
  {
    RegCloseKey(handle:_acx_hklm);
    NetUseDel();
    _acx_hklm = NULL;
    _acx_init = FALSE;
  }
}



#---------------------------------------------------------#
# Function    : activex_is_installed                      #
# Description : Check if given control is installed.      #
# Return      : TRUE if installed;                        #
#               FALSE if not;                             #
#               NULL if problem.                          #
#---------------------------------------------------------#
function activex_is_installed(clsid)
{
  local_var name;

  name = activex_get_name(clsid:clsid);
  if (isnull(name)) return NULL;
  # nb: are there controls that don't have a name???
  else if (strlen(name)) return TRUE;
  else return FALSE;
}


#---------------------------------------------------------#
# Function    : activex_get_name                          #
# Description : Get name for given control.               #
# Return      : name if installed;                        #
#               empty string if not;                      #
#               NULL if problem.                          #
#---------------------------------------------------------#
function activex_get_name(clsid)
{
  local_var key, key_h, name, value;

  if (_acx_init == FALSE) 
  {
    if (activex_init() != ACX_OK ) return NULL;
  }
  if (isnull(_acx_hklm)) return NULL;
  if (isnull(clsid)) return NULL;

  if (clsid[0] != '{') clsid = '{' + clsid;
  if (clsid[strlen(clsid)-1] != '}') clsid = clsid + '}';

  name = "";
  key = "SOFTWARE\Classes\CLSID\" + clsid;
  key_h = RegOpenKey(handle:_acx_hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(value)) name = value[1];
    RegCloseKey(handle:key_h);
  }
  return name;
}


#---------------------------------------------------------#
# Function    : activex_get_filename                      #
# Description : Get filename of handler for given         #
#               control.                                  #
# Return      : filename if installed;                    #
#               empty string if not;                      #
#               NULL if problem.                          #
#---------------------------------------------------------#
function activex_get_filename(clsid)
{
  local_var fh, key, key_h, filename, obj, rc, share, subkey, subkeys, value;

  if (_acx_init == FALSE) 
  {
    if (activex_init() != ACX_OK ) return NULL;
  }
  if (isnull(_acx_hklm)) return NULL;
  if (isnull(clsid)) return NULL;

  if (clsid[0] != '{') clsid = '{' + clsid;
  if (clsid[strlen(clsid)-1] != '}') clsid = clsid + '}';

  rc = activex_is_installed(clsid:clsid);
  if (isnull(rc)) return NULL;
  else if (rc == FALSE) return "";

  filename = "";
  subkeys = make_list(
    "InprocServer32",
    "LocalServer32",
    "InprocHandler32",
    "InprocServer",
    "LocalServer",
    "InprocHandler"
  );
  foreach subkey (subkeys)
  {
    key = "SOFTWARE\Classes\CLSID\" + clsid + "\" + subkey;
    key_h = RegOpenKey(handle:_acx_hklm, key:key, mode:MAXIMUM_ALLOWED);
    if (!isnull(key_h))
    {
      value = RegQueryValue(handle:key_h, item:NULL);
      if (!isnull(value)) 
      {
        filename = value[1];
        if (filename[0] == '"') filename = substr(filename, 1);
        if (filename[strlen(filename)-1] == '"') 
          filename = substr(filename, 0, strlen(filename)-2);
      }
      RegCloseKey(handle:key_h);
    }
    if (filename) break;
  }

  # Make sure the file actually exists.
  if (filename)
  {
    RegCloseKey(handle:_acx_hklm);
    NetUseDel(close:FALSE);
    _acx_hklm = NULL;

    share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:filename);
    obj = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:filename);

    rc = NetUseAdd(share:share);
    if (rc == 1)
    {
      fh = CreateFile(
        file:obj,
        desired_access:GENERIC_READ,
        file_attributes:FILE_ATTRIBUTE_NORMAL,
        share_mode:FILE_SHARE_READ,
        create_disposition:OPEN_EXISTING
      );
      if (isnull(fh)) filename = "";
      else CloseFile(handle:fh);
    }
    NetUseDel(close:FALSE);

    rc = NetUseAdd(share:"IPC$");
    if (rc != 1)
    {
      NetUseDel();
      return NULL;
    }

    _acx_hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
    if (isnull(_acx_hklm))
    {
      NetUseDel();
      return NULL;
    }
  }

  return filename;
}


#---------------------------------------------------------#
# Function    : activex_get_killbit                       #
# Description : Get "kill bit" for the given control.     #
# Return      : TRUE if "kill bit" set;                   #
#               FALSE if not;                             #
#               -1 if control doesn't exist;              #
#               NULL if problem.                          #
#---------------------------------------------------------#
function activex_get_killbit(clsid)
{
  local_var key, key_h, killbit, value;

  if (_acx_init == FALSE) 
  {
    if (activex_init() != ACX_OK ) return NULL;
  }
  if (isnull(_acx_hklm)) return NULL;
  if (isnull(clsid)) return NULL;

  if (clsid[0] != '{') clsid = '{' + clsid;
  if (clsid[strlen(clsid)-1] != '}') clsid = clsid + '}';

  key = "SOFTWARE\Microsoft\Internet Explorer\ActiveX Compatibility\" + clsid +  "";
  key_h = RegOpenKey(handle:_acx_hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:"Compatibility Flags");
    if (!isnull(value))
    {
      killbit = (value[1] & 0x400) == 0x400;
      return killbit;
    }
    RegCloseKey(handle:key_h);
  }
  return NULL;
}


#---------------------------------------------------------#
# Function    : activex_get_fileversion                   #
# Description : Get version of the given control.         #
# Return      : file version as a string;                 #
#               NULL if problem (eg, control doesn't      #
#                 exist, can't connect to share, etc.)    #
#---------------------------------------------------------#
function activex_get_fileversion(clsid)
{
  local_var fh, file, obj, rc, share, ver, version;

  if (_acx_init == FALSE) 
  {
    if (activex_init() != ACX_OK ) return NULL;
  }
  if (isnull(_acx_hklm)) return NULL;
  if (isnull(clsid)) return NULL;

  if (clsid[0] != '{') clsid = '{' + clsid;
  if (clsid[strlen(clsid)-1] != '}') clsid = clsid + '}';

  file = activex_get_filename(clsid:clsid);
  if (!file) return NULL;

  version = get_kb_item("SMB/FileVersions"+tolower(str_replace(string:file, find:"\", replace:"/")));
  if (!isnull(version)) return version;

  RegCloseKey(handle:_acx_hklm);
  NetUseDel(close:FALSE);
  _acx_hklm = NULL;

  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:file);
  obj = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:file);

  version = NULL;
  rc = NetUseAdd(share:share);
  if (rc == 1)
  {
    fh = CreateFile(
      file:obj,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );
    if (!isnull(fh))
    {
      ver = GetFileVersion(handle:fh);
      if (!isnull(ver))
      {
        version = ver[0] + '.' + ver[1] + '.' + ver[2] + '.' + ver[3];
        set_kb_item(
          name:"SMB/FileVersions"+tolower(str_replace(string:file, find:"\", replace:"/")), 
          value:version
        );
      }
      CloseFile(handle:fh);
    }
  }
  NetUseDel(close:FALSE);

  rc = NetUseAdd(share:"IPC$");
  if (rc != 1)
  {
    NetUseDel();
    return NULL;
  }

  _acx_hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
  if (isnull(_acx_hklm))
  {
    NetUseDel();
    return NULL;
  }

  return version;
}


#---------------------------------------------------------#
# Function    : activex_check_fileversion                 #
# Description : Checks fileversion of the given control.  #
# Return      : TRUE if present and strictly less than    #
#                 any specified version;                  #
#               FALSE if not;                             #
#               NULL if problem.                          #
#---------------------------------------------------------#
function activex_check_fileversion(clsid, fix)
{
  local_var i, ifix, iver, rc, ver;

  rc = activex_is_installed(clsid:clsid);
  if (isnull(rc)) return NULL;
  else if (rc == FALSE) return FALSE;

  ver = activex_get_fileversion(clsid:clsid);
  if (isnull(ver)) return NULL;
  if (isnull(fix)) return TRUE;

  iver = split(ver, sep:'.', keep:FALSE);
  for (i=0; i<max_index(iver); i++)
    iver[i] = int(iver[i]);

  ifix = split(fix, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ifix); i++)
    ifix[i] = int(ifix[i]);

  for (i=0; i<max_index(ifix); i++)
    if ((iver[i] < ifix[i]))
    {
      return TRUE;
    }
    else if (iver[i] > ifix[i])
      break;
  return FALSE;
}
