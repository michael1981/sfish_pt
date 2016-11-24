#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25348);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2007-2972", "CVE-2007-2973", "CVE-2007-2974");
  script_bugtraq_id(24187, 24239);
  script_xref(name:"OSVDB", value:"36710");
  script_xref(name:"OSVDB", value:"36711");
  script_xref(name:"OSVDB", value:"36712");

  script_name(english:"AntiVir File Handling Vulnerabilities");
  script_summary(english:"Checks version of AntiVir"); 

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Avira AntiVir, an antivirus software
application. 

The version of AntiVir installed on the remote host is reportedly
prone to a buffer overflow in its LZH file processing code as well as
denial of service vulnerabilities when parsing UPX and TAR files.  An
attacker may be able to exploit these issues to execute arbitrary code
on the remote host, likely with LOCAL SYSTEM privileges, to crash the
remote antivirus engine, or to cause the CPU to enter an endless loop." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2007-05/0506.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2007-05/0512.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2007-05/0545.html" );
 script_set_attribute(attribute:"see_also", value:"http://forum.antivir-pe.de/thread.php?threadid=22528" );
 script_set_attribute(attribute:"solution", value:
"Use AntiVir's Update feature to upgrade to the latest version." );
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


# Grab installation path and version from the registry.
paths =  make_array();

prod = "Premium Security Suite";
key = "SOFTWARE\Avira\Premium Security Suite";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"Path");
  if (!isnull(value)) 
  {
    path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:value[1]);
    paths[prod] = path;
  }

  RegCloseKey (handle:key_h);
}

prod = "AntiVir Windows Server";
key = "SOFTWARE\H+BEDV\AVNetNT";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"Path");
  if (!isnull(value)) 
  {
    path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:value[1]);
    paths[prod] = path;
  }

  RegCloseKey (handle:key_h);
}

prod = "AntiVir Windows Workstation";
key = "SOFTWARE\H+BEDV\AntiVir Workstation";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"Path");
  if (!isnull(value)) 
  {
    path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:value[1]);
    paths[prod] = path;
  }

  RegCloseKey (handle:key_h);
}
RegCloseKey(handle:hklm);


# If it's installed...
if (max_index(keys(paths)) > 0)
{
  foreach prod (keys(paths))
  {
    path = paths[prod];

    # Look at the affected files.
    share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
    avpack =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\avpack32.dll", string:path);
    engine =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\avewin32.dll", string:path);
    NetUseDel(close:FALSE);

    rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
    if (rc != 1)
    {
      NetUseDel();
      exit(0);
    }

    ver_avpack = NULL;
    fh = CreateFile(
      file:avpack,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );
    if (!isnull(fh))
    {
      ver_avpack = GetFileVersion(handle:fh);
      CloseFile(handle:fh);
    }

    ver_engine = NULL;
    fh = CreateFile(
      file:engine,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );
    if (!isnull(fh))
    {
      ver_engine = GetFileVersion(handle:fh);
      CloseFile(handle:fh);
    }

    # Check the version numbers.
    affected = FALSE;
    if (!vuln && !isnull(ver_avpack))
    {
      fix = split("7.03.00.09", sep:'.', keep:FALSE);
      for (i=0; i<max_index(fix); i++)
        fix[i] = int(fix[i]);

      for (i=0; i<max_index(ver_avpack); i++)
        if (ver_avpack[i] < fix[i])
        {
          affected = TRUE;
          break;
        }
        else if (ver_avpack[i] > fix[i])
          break;
    }
    if (!affected && !isnull(ver_engine))
    {
      fix = split("7.04.00.24", sep:'.', keep:FALSE);
      for (i=0; i<max_index(fix); i++)
        fix[i] = int(fix[i]);

      for (i=0; i<max_index(ver_engine); i++)
        if (ver_engine[i] < fix[i])
        {
          affected = TRUE;
          break;
        }
        else if (ver_engine[i] > fix[i])
          break;
    }

    if (affected == TRUE)
    {
      report = string(
        "Nessus found an affected version of ", prod, "\n",
        "installed under :\n",
        "\n",
        "  ", path
      );
      security_hole(port:port, extra:report);
      break;
    }
  }
}


# Clean up.
NetUseDel();
