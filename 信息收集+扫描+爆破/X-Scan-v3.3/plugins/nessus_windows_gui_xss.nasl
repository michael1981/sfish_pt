#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25612);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2007-3546");
  script_bugtraq_id(24677);
  script_xref(name:"OSVDB", value:"37011");

  script_name(english:"Nessus Windows < 3.0.6 GUI Unspecified XSS");
  script_summary(english:"Checks version of Nessus"); 

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is susceptible to
a cross-site scripting attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the Nessus Windows GUI. 

The version of the Nessus Windows GUI installed on the remote host
fails to sanitize user-supplied input before using it to generate
dynamic content.  An unauthenticated remote attacker may be able to
leverage this issue to inject arbitrary HTML or script code into a
user's browser to be executed within the security context of the
affected host." );
 script_set_attribute(attribute:"see_also", value:"http://mail.nessus.org/pipermail/nessus-announce/2007-June/msg00001.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Nessus for Windows version 3.0.6 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);
  exit(0);
}

#

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


# Get some info about the install.
path = NULL;

key = "SOFTWARE\Tenable\Nessus";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"PATH");
  if (!isnull(value))
  {
    path = value[1];
    path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);


# If it is...
if (path)
{
  # Make sure the executable exists.
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\NessusGUI.exe", string:path);
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
  if (!isnull(fh))
  {
    ver = GetFileVersion(handle:fh);
    CloseFile(handle:fh);
  }

  # There's a problem if the version is < 3.0.6
  if (!isnull(ver))
  {
    fix = split("3.0.6.0", sep:'.', keep:FALSE);
    for (i=0; i<4; i++)
      fix[i] = int(fix[i]);

    for (i=0; i<max_index(ver); i++)
      if ((ver[i] < fix[i]))
      {
        # nb: only the first 3 parts are reported to end-users.
        version = string(ver[0], ".", ver[1], ".", ver[2]);

        report = string(
          "The Nessus Windows GUI ", version, " is installed under :\n",
          "\n",
          "  ", path, "\n"
        );
        security_warning(port:port, extra: report);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
        break;
      }
      else if (ver[i] > fix[i])
        break;
  }
}


# Clean up.
NetUseDel();
