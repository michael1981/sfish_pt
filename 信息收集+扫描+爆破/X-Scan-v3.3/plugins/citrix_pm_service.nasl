#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40616);
  script_version("$Revision: 1.1 $");
  
  script_bugtraq_id(35133);
  script_xref(name:"OSVDB", value:"54779");
  script_xref(name:"Secunia", value:"35229");

  script_name(english:"Citrix Password Manager Service Stored Secondary Credentials Disclosure");
  script_summary(english:"Checks version of Citrix Password Manager Service"); 

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote Windows host has an application that is affected by an\n",
      "information disclosure vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
     "Citrix Password Manager Service is installed on the remote host.\n",
      "\n",
      "The version of Citrix Password Manager Service on the remote host is \n",
      "reportedly affected by an information disclosure vulnerability\n",
      "involving secondary credentials."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.citrix.com/article/CTX120743"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Citrix Password Manager version 4.6 SP1 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N"
  );
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/05/27"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2008/05/27"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/08/17"
  );
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
if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "SMB/Registry/Enumerated KB item is missing.");

name    =  kb_smb_name();
port    =  kb_smb_transport();
if (!get_port_state(port)) exit(0);
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

soc = open_sock_tcp(port);
if (!soc) exit(1, "Can't open socket.");

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

# Check whether it's installed.
path = NULL;

key = "SOFTWARE\Citrix\MetaFrame Password Manager\Service";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"ProductInstallPath");
  if (!isnull(value))
  {
    path = value[1];
    path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
  }
  RegCloseKey (handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0, "The software is not installed.");
}

# Determine the version.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\ServiceConfigurationTool.exe", string:path);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to "+share+" share.");
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
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
  NetUseDel();

  # There's a problem if the version of Citrix Password Manager Service is earlier than 4.6.264.
  if (!isnull(ver))
  {
    if ( ver[0] < 4 || ( ver[0] == 4 && ver[1] < 6) || ( ver[0] == 4 && ver[1] == 6 && ver[2] < 264 ) )
    {
      version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);

      report = string(      
        "\n",
        "Version ", version, " of the Citrix Password Manager Service is installed under :\n",
        "\n",
        "  ", path, "\n"
      );
      security_warning(port:port, extra:report);
      exit(0);
    }
    else exit(0, "The host is not affected.");
  }
  else exit(1, "'GetFileVersion()' returned NULL.");
}
else
{
  NetUseDel();
  exit(1, "Can't read '"+path+"\ServiceConfigurationTool.exe'.");
}
