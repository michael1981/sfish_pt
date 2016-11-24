#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27040);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2007-4619");
  script_bugtraq_id(26042);
  script_xref(name:"OSVDB", value:"41694");

  script_name(english:"Winamp < 5.5 FLAC Plug-in Multiple Buffer Overflows");
  script_summary(english:"Checks the version number of Winamp"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a multimedia application that is
affected by multiple buffer overflow vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is using Winamp, a popular media player for Windows. 

The version of Winamp installed on the remote Windows host contains a
plug-in to handle playing FLAC files that contains several integer
buffer overflow vulnerabilities.  If an attacker can trick a user on
the affected host into opening a specially-crafted FLAC file, he may
be able to leverage this issue to execute arbitrary code on the host
subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=608" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/482115/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.winamp.com/player/version-history" );
 script_set_attribute(attribute:"see_also", value:"http://forums.winamp.com/showthread.php?threadid=278538" );
 script_set_attribute(attribute:"solution", value:
"Either upgrade to Winamp version 5.5 or later or remove the FLAC Input
Plug-in (in_flac.dll)." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );


script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
  script_dependencies("winamp_in_cdda_buffer_overflow.nasl", "smb_enum_services.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/Winamp/Version", "SMB/Winamp/Path", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);
  exit(0);
}

#

include("smb_func.inc");


# Get version of Winamp.

#
# nb: the KB item is based on GetFileVersion, which may differ
#     from what the client reports.

ver = get_kb_item("SMB/Winamp/Version");

# If it's < 5.5, check for FLAC Input Plug-in.

if (ver && ver =~ "^([0-4]\.|5\.([0-2]\.|[0-4]\.))")
{
  path = get_kb_item("SMB/Winamp/Path");
  if (isnull(path)) exit(0);

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
  if (rc != 1)
  {
    NetUseDel();
    exit(0);
  }

  # Check whether the FLAC input plug-in exists.
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Plugins\in_flac.dll", string:path);

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
  if (!isnull(fh))
  {
    CloseFile(handle:fh);

    report = string(
      "Winamp version ", ver, " is installed on the remote host, and it\n",
      "includes the FLAC Input Plug-in :\n",
      "\n",
      "  ", path, "\\Plugins\\in_flac.dll\n"
    );
    security_hole(port:port, extra:report);
  }

  # Clean up.
  NetUseDel();
}
