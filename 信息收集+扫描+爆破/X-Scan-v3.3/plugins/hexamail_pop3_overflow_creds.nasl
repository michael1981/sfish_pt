#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(26016);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2007-4646");
  script_bugtraq_id(25496);
  script_xref(name:"OSVDB", value:"40171");

  script_name(english:"Hexamail Server pop3 Service USER Command Remote Overflow (credentialed check)");
  script_summary(english:"Checks version of hexamailserver.exe");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a program that is affected by a buffer
overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"According to its version, the installation of Hexamail on the remote
host is affected by a buffer overflow in its POP3 service component
that can be exploited by an unauthenticated remote attacker to crash
the service or to execute arbitrary code on the affected host with
LOCAL SYSTEM privileges." );
 script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/hexamail_bof.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/4344" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Hexamail version 3.0.1.004 or later as that reportedly
resolves the issue." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );


script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");


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
  exit(0);
}


# Check whether it's installed.
path = NULL;

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Hexamail Server";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"InstallLocation");
  if (!isnull(value))
  {
    path = value[1];
  }

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0);
}


# Check the version of the main exe.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\hexamailserver.exe", string:path);
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
        (get_word(blob:varfileinfo['Translation'], pos:0) << 16) +
        get_word(blob:varfileinfo['Translation'], pos:2);
      translation = toupper(display_dword(dword:translation, nox:TRUE));
    }
    stringfileinfo = children['StringFileInfo'];
    if (!isnull(stringfileinfo) && !isnull(translation))
    {
      data = stringfileinfo[translation];
      if (isnull(data)) data = stringfileinfo[tolower(translation)];
      if (!isnull(data)) version = data['ProductVersion'];
    }
  }
  CloseFile(handle:fh);
}
NetUseDel();


# Check the version number.
if (!isnull(version))
{
  version = str_replace(find:",", replace:".", string:version);

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fix = split("3.0.1.004", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      report = string(
        "Version ", version, " of Hexamail is installed under :\n",
        "\n",
        "  ", path
      );
      security_hole(port:port, extra:report);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}
