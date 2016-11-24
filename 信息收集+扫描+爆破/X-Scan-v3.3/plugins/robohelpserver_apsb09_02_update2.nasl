#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(35737);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2009-0523");
  script_bugtraq_id(33887);
  script_xref(name:"OSVDB", value:"52744");
  script_xref(name:"Secunia", value:"34048");

  script_name(english:"RoboHelp Server Multiple Cross-Site Scripting Vulnerabilities (APSB09-02 Update 2)");
  script_summary(english:"Checks for patched files"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by
multiple cross-site scripting vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"Adobe RoboHelp Server version 6 or 7 is installed on the remote host,
and it is missing updates included with Adobe security advisory
'APSB09-02 Update 2' involving the files 'redirect.asp',
'Report_Template.asp' and 'SQL_Lib.asp'.  Provided an attacker has
access to 'RoboHelp Help Errors log' or is able to trick an user with
access to 'RoboHelp Help Errors log' to click on a malicious link, it
may be possible for him to execute arbitrary HTML and script code in
the victim's browser session." );
 script_set_attribute(attribute:"see_also", value:
"http://www.adobe.com/support/security/bulletins/apsb09-02.html" );
 script_set_attribute(attribute:"solution", value:
"Apply the patch referenced in the vendor advisory above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
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


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


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

# Make sure it's installed.
path = NULL;

key = "SOFTWARE\Adobe\RoboHelp Server";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    if (strlen(subkey) && subkey =~ "^[0-9]+\.")
    {
      key2 = key + "\" + subkey + "\System";
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        item = RegQueryValue(handle:key2_h, item:"InstallPath");
        if (!isnull(item))
        {
          path = item[1];
          path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
        }
        RegCloseKey(handle:key2_h);
      }
    }
  }
  RegCloseKey (handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0);
}

# Determine the version of Robo.dll.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
dll = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\bin\Robo.dll", string:path);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

fh = CreateFile(
  file:dll,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

ver = NULL;
if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}

vuln = FALSE;
# If it's an affected version...
if (
  !isnull(ver) && 
  (
    (ver[0] == 7) || (ver[0] == 6)
  )
)
{
  # Check if each affected file has been patched.
  files = make_list(
    "redirect.asp", 
    "Report_Template.asp",
    "SQL_Lib.asp"
  );

  foreach file (files)
  {
    asp = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Reports\"+file, string:path);
    NetUseDel(close:FALSE);

    rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
    if (rc != 1)
    {
      NetUseDel();
      break;
    }

    fh = CreateFile(
      file:asp,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );
    if (!isnull(fh))
    {
      # Read an initial chunk.
      chunk = 35000;
      size = GetFileSize(handle:fh);
      if (size > 0)
      {
        if (chunk > size) chunk = size;
        data = ReadFile(handle:fh, length:chunk, offset:0);

        if(data)
        {
          if (
            file == 'redirect.asp' && 
            'if (<%=bSafe%>)' >!< data
          ) vuln = TRUE;
          else if (
            file == 'Report_Template.asp' && 
            'function escapeForXSS' >!< data
          ) vuln = TRUE;
          else if (
            file == 'SQL_Lib.asp' && 
            'escapeForXSS(' >!< data
          ) vuln = TRUE;
        }
      }
      CloseFile(handle:fh);

      if (vuln) break;
    }
  }
}
NetUseDel();

# Report if an issue was found.
if (vuln)
{
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  security_warning(port);
}
