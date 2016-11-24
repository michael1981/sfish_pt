#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42261);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2009-3522", "CVE-2009-3523", "CVE-2009-3524");
  script_bugtraq_id(36507, 36796, 36888);
  script_xref(name:"OSVDB", value:"58402");
  script_xref(name:"OSVDB", value:"58403");
  script_xref(name:"OSVDB", value:"58493");
  script_xref(name:"Secunia", value:"36858");

  script_name(english:"Avast! Professional Edition < 4.8.1356 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Avast! Professional Edition");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote Windows host contains an application that is affected by\n",
      "multiple vulnerabilities."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The remote Windows host is running Avast! Professional Edition.\n",
      "\n",
      "The installed version of Avast! Professional Edition is potentially\n",
      "affected by multiple issues :\n",
      "\n",
      "  - A local privilege escalation vulnerability because the \n",
      "    'avast4.ini' file is created with insecure permissions on\n",
      "    setup. (CVE-2009-3524)\n",
      "\n",
      "  - A local privilege escalation vulnerability because the\n",
      "    'aswMov2.sys' driver fails to sufficiently sanitize\n",
      "    user-supplied input passed to 'IOCTL'. (CVE-2009-3522)\n",
      "\n",
      "  - A local privilege escalation vulnerability because the\n",
      "    'aavmKer4.sys' driver fails to sufficiently sanitize\n",
      "    user-supplied input passed to 'IOCTL'. (CVE-2009-3523)\n",
      "\n"
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/507375/30/0/threaded"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/506681/30/0/threaded"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.ntinternals.org/ntiadv0904/ntiadv0904.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.avast.com/eng/avast-4-home_pro-revision-history.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Avast! Professional Edition 4.8.1356 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/09/25"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/09/25"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/10/27"
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

include("smb_func.inc");

if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "The 'SMB/Registry/Enumerated' KB item is missing.");

# Connect to the appropriate share.
name    = kb_smb_name();
port    = kb_smb_transport();
if (!get_port_state(port)) exit(1, "Port "+port+" is not open.");
login   = kb_smb_login();
pass    = kb_smb_password();
domain  = kb_smb_domain();

soc = open_sock_tcp(port);
if (!soc) exit(1, "Can't open socket on port "+port+".");

session_init(socket:soc, hostname:name);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to IPC$ share.");
}

# Connect to the remote registry
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Can't connect to the remote registry.");
}

# Grab the installation path and product info from the registry.
path = NULL;
prod = NULL;

key = "SOFTWARE\ALWIL Software\Avast\4.0";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"Avast4ProgramFolder");
  if (!isnull(value)) path = value[1];

  value = RegQueryValue(handle:key_h, item:"Product");
  if (!isnull(value)) prod = value[1];
  
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

# If its installed...
if (!isnull(path) && prod == "av_pro")
{
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  dll = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\aswEngin.dll",string:path);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(1, "Can't connect to '"+share+"' share.");
  }

  fh = CreateFile(
    file:dll,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (isnull(fh)) exit(1, "Can't open the file '"+path+"\\aswEngin.dll'.");
  
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);

}

#Clean Up
NetUseDel();

if (!isnull(ver))
{
  version = string(ver[0], ".", ver[1], ".", ver[2]);

  #Check the version number.
  fixed_version = "4.8.1356";
  fix = split(fixed_version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if (ver[i] < fix[i])
    {
      report = string(
        "\n",
        "Product           : Avast! Professional Edition\n",
        "Path              : ", path, "\n",
        "Installed version : ", version, "\n",
        "Fixed version     : ", fixed_version, "\n"
      );
      security_hole(port:port, extra:report);
      exit(0);
    }
    else if(ver[i] > fix[i])
    {
      break;
    }
  exit(0, "Avast! Professional Edition version " + version + " is not affected.");
}
