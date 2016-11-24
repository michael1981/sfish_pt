#
# (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(23755);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2006-6239");
  script_bugtraq_id(21325);
  script_xref(name:"OSVDB", value:"30694");

  script_name(english:"MailEnable NetWebAdmin Unauthorized Access (ME-10019)");
  script_summary(english:"Checks version of MailEnable's NETWebAdmin.dll");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that allows unauthorized
access." );
 script_set_attribute(attribute:"description", value:
"The remote version of MailEnable contains a web-based administration
tool that allows a user to login with a blank password." );
 script_set_attribute(attribute:"see_also", value:"http://www.mailenable.com/hotfix/" );
 script_set_attribute(attribute:"solution", value:
"Apply Hotfix ME-10019." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("mailenable_detect.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/MailEnable/Installed", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


if (!get_kb_item("SMB/MailEnable/Installed")) exit(0);
if (get_kb_item("SMB/MailEnable/Standard")) prod = "Standard";
if (get_kb_item("SMB/MailEnable/Professional")) prod = "Professional";
else if (get_kb_item("SMB/MailEnable/Enterprise")) prod = "Enterprise";


# Make sure we're looking at Professional / Enterprise 2.32, which is
# the only version affected according to NetWebAdmin-ReadMe.txt.
if (prod == "Professional" || prod == "Enterprise")
{
  ver = get_kb_item("SMB/MailEnable/"+prod+"/Version");
  path = get_kb_item("SMB/MailEnable/"+prod+"/Path");
  if (!isnull(ver) && !isnull(path) && ver == "2.32")
  {
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

    share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
    dll = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\bin\NETWebAdmin\bin\NETWebAdmin.dll", string:path);

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
      ver2 = GetFileVersion(handle:fh);
      CloseFile(handle:fh);

      # Check the version.
      if (!isnull(ver2))
      {
        fix = split("1.0.2505.31553", sep:'.', keep:FALSE);
        for (i=0; i<4; i++)
          fix[i] = int(fix[i]);

        for (i=0; i<max_index(ver2); i++)
          if ((ver2[i] < fix[i]))
          {
            security_hole(port);
            break;
          }
          else if (ver2[i] > fix[i])
            break;
      }
    }

    # Clean up.
    NetUseDel();
  }
}
