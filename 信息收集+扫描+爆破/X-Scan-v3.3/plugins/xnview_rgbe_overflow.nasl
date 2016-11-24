#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(30130);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2008-0064");
  script_bugtraq_id(27514);
  script_xref(name:"OSVDB", value:"42832");

  script_name(english:"XnView RGBE File Handling Buffer Overflow");
  script_summary(english:"Checks version of xnview.exe");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that reportedly is
affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"XnView, an application to view and convert graphic files, is installed
on the remote host. 

The version of XnView on the remote host reportedly contains a stack-
based buffer overflow that can be triggered when reading a specially-
crafted Radiance RGBE ('.hdr') file.  If an attacker can trick a user
on the affected host into opening such a file, he may be able to
leverage this issue to execute arbitrary code on the host subject to
the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2008-1/advisory/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to XnView version 1.92.1 or later as that reportedly resolves
the issue." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
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


function display_dword (dword, nox)
{
 local_var tmp;

 if (isnull(nox) || (nox == FALSE))
   tmp = "0x";
 else
   tmp = "";

 return string (tmp,
               toupper(
                  hexstr(
                    raw_string(
                               (dword >>> 24) & 0xFF,
                               (dword >>> 16) & 0xFF,
                               (dword >>> 8) & 0xFF,
                               dword & 0xFF
                              )
                        )
                      )
               );
}


# Figure out where the installer recorded information about it.
key = NULL;

list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (isnull(list)) exit(0);

foreach name (keys(list))
{
  prod = list[name];
  if (prod && prod =~ "^XnView")
  {
    key = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(.+)\/DisplayName$", replace:"\1", string:name);
    key = str_replace(find:"/", replace:"\", string:key);
    break;
  }
}
if (isnull(key)) exit(0);


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


# Find out where it was installed.
path = NULL;

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"InstallLocation");
  if (!isnull(item)) 
  {
    path = item[1];
    path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
  }
  RegCloseKey(handle:key_h);
}
if (isnull(path))
{
  RegCloseKey(handle:hklm);
  NetUseDel();
  exit(0);
}


# Determine the version of XnView.exe.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\XnView.exe", string:path);
NetUseDel(close:FALSE);

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
version = NULL;
if (!isnull(fh))
{
  ret = GetFileVersionEx(handle:fh);
  if (!isnull(ret)) children = ret['Children'];
  if (!isnull(children))
  {
    varfileinfo = children['VarFileInfo'];
    if (!isnull(varfileinfo))
    {
      translation = 
        (get_word (blob:varfileinfo['Translation'], pos:0) << 16) +
        get_word (blob:varfileinfo['Translation'], pos:2);
      translation = toupper(display_dword(dword:translation, nox:TRUE));
    }
    stringfileinfo = children['StringFileInfo'];
    if (!isnull(stringfileinfo) && !isnull(translation))
    {
      data = stringfileinfo[tolower(translation)];
      if (!isnull(data)) version = data['ProductVersion'];
    }
  }
  CloseFile(handle:fh);
}
NetUseDel();


# Check the version number.
if (!isnull(version))
{
  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fix = split("1.92.1", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      if (report_verbosity)
      {
        report = string(
          "XnView version ", version, " is installed under :\n",
          "\n",
          "  ", path, "\n"
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);

      break;
    }
    else if (ver[i] > fix[i])
      break;
}
