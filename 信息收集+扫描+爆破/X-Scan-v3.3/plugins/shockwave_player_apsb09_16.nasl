#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42369);
  script_version("$Revision: 1.2 $");

  script_cve_id(
    "CVE-2009-3244", 
    "CVE-2009-3463",
    "CVE-2009-3464",
    "CVE-2009-3465",
    "CVE-2009-3466"
  );
  script_bugtraq_id(36905);
  script_xref(name:"OSVDB", value:"58209");
  script_xref(name:"OSVDB", value:"59699");
  script_xref(name:"OSVDB", value:"59700");
  script_xref(name:"OSVDB", value:"59701");
  script_xref(name:"OSVDB", value:"59702");

  script_name(english:"Shockwave Player APSB09-016");
  script_summary(english:"Checks version of Shockwave Player");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote Windows host contains a web browser plugin which is affected\n",
      "by multiple vulnerabilities.\n"
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The remote Windows host contains a version of Adobe's Shockwave Player\n",
      "that is earlier than 11.5.0.602.  Such versions are affected by \n",
      "multiple issues :\n",
      "\n",
      "  - An invalid index vulnerability could lead to code\n",
      "    execution. (CVE-2009-3463)\n",
      "\n",
      "  - Invalid pointer vulnerabilities could lead to code\n",
      "    execution. (CVE-2009-3464, CVE-2009-3465)\n",
      "\n",
      "  - An invalid string length vulnerability could potentially\n",
      "    lead to code execution. (CVE-2009-3466)\n",
      "\n",
      "  - A boundary condition issue could lead to a denial\n",
      "    of service. (CVE-2009-3244)\n"
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.adobe.com/support/security/bulletins/apsb09-16.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Adobe Shockwave version 11.5.0.602 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/11/03"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/11/03"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/11/04"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139,445);

  exit(0);
}

include("global_settings.inc");
include("smb_func.inc");

#Connect to the appropriate share.
if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "The 'SMB/Registry/Enumerated' KB item is missing.");
name    = kb_smb_name();
port    = kb_smb_transport();
if (!get_port_state(port)) exit(1, "Port "+port+" is not open.");
login   = kb_smb_login();
pass    = kb_smb_password();
domain  = kb_smb_domain();

soc = open_sock_tcp(port);
if (!soc) exit(1, "Can't open a socket on TCP port "+port+".");

session_init(socket:soc, hostname:name);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to IPC$ share.");
}

#Connect to remote registry
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Can't connect to the remote registry.");
}

#Check whether it's installed
variants = make_array();

# - check for the browser plugin
key = "SOFTWARE\MozillaPlugins\@adobe.com/ShockwavePlayer";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"Path");
  if (!isnull(item))
  {
    file = item[1];
    variants[file] = "Plugin";
  }
  RegCloseKey(handle:key_h);
}
key = "SOFTWARE\Mozilla";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    if (strlen(subkey) && subkey =~ "^Mozilla Firefox ")
    {
      key2 = key + "\" + subkey + "\Extensions";
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        item = RegQueryValue(handle:key2_h, item:"Plugins");
        if (!isnull(item))
        {
          file = item[1] + "\np32dsw.dll";
          variants[file] = "Plugin";
        }
        RegCloseKey(handle:key2_h);
      }
    }
  }
  RegCloseKey(handle:key_h);
}

opera_path = get_kb_item("SMB/Opera/Path");
if (!isnull(opera_path))
{
  # nb: we'll check later whether this actually exists.
  file = opera_path + "Program\Plugins\NPSWF32.dll";
  variants[file] = "Plugin";
}

#Check for the ActiveX control
clsids = make_list(
  '{4DB2E429-B905-479A-9EFF-F7CBD9FD52DE}',
  '{233C1507-6A77-46A4-9443-F871F945D258}',
  '{166B1BCA-3F9C-11CF-8075-444553540000}'     #used in versions <= 10.x
);
foreach clsid (clsids)
{
  key = "SOFTWARE\Classes\CLSID\" + clsid + "\InprocServer32";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(item))
    {
      file = item[1];
      variants[file] = "ActiveX";
    }
    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);
if (max_index(keys(variants)) == 0)
{
  NetUseDel();
  exit(0, "Shockwave Player is not installed.");
}

#Determine the version of each instance found.
files = make_array();
info = "";

foreach file (keys(variants))
{
  #Don't report again if the name differs only in its case.
  if (files[tolower(file)]++) continue;

  variant = variants[file];

  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:file);
  file2 = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:file);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(1, "Can't connect to "+share+" share.");
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
    ver = GetFileVersion(handle:fh);
    if (
      !isnull(ver) &&
      (
        ver[0] < 11 ||
        (
          ver[0] == 11 &&
          (
            ver[1] < 5 ||
            (
              ver[1] == 5 &&
              (
                ver[2] < 2 ||
                (ver[2] == 2 && ver[3] < 602)
              )
            )
          )
        )
      )
    )
    {
      version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);

      if (variant == "Plugin")
      {
        info += '  - Browser Plugin (for Firefox / Netscape / Opera) :\n';
      }
      else if (variant == "ActiveX")
      {
        info += '  - ActiveX control (for Internet Explorer) :\n';
      }
      info += '    ' + file + ', ' + version + '\n';
    }
    CloseFile(handle:fh);
  }
  NetUseDel(close:FALSE);
}
NetUseDel();

if (!info) exit(0, "No vulnerable installs of Shockwave Player were found.");

if (report_verbosity > 0)
{
  if (max_index(split(info)) > 2) s = "s";
  else s = "";

  report = string(
    "\n",
    "Nessus has identified the following vulnerable instance", s, " of Shockwave\n",
    "Player installed on the remote host :\n",
    "\n",
    info
  );
  security_hole(port:port, extra:report);
}
else security_hole(port:port);
