#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(20212);
  script_version("$Revision: 1.7 $");

  script_name(english:"XCP DRM Software Detection");
  script_summary(english:"Checks whether XCP DRM Software is installed"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a rootkit installed on it." );
 script_set_attribute(attribute:"description", value:
"First 4 Internet's Extended Copy Protection (XCP) digital rights
management software is installed on the remote Windows host.  While it
is not malicious per se, the software hides files, processes, and
registry keys / values from ordinary inspection, which has been
exploited by several viruses to hide from anti-virus software." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?13c4c8b5" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?572228eb" );
 script_set_attribute(attribute:"see_also", value:"http://www.sophos.com/pressoffice/news/articles/2005/11/stinxe.html" );
 script_set_attribute(attribute:"solution", value:
"On the affected host, run the DOS command 'cmd /k sc delete
$sys$aries' to deactivate the software and reboot." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("smb_enum_services.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/svcs", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");


# Check whether either of the two services XCP installs are running.
services = get_kb_item("SMB/svcs");
if (
  services &&
  (
    "XCP CD Proxy" >< services ||
    "Plug and Play Device Manager" >< services
  )
) {
  # Identify the location of the file cloaking device driver.
  winroot = hotfix_get_systemroot();
  if (!winroot) exit(1);
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:winroot);
  file =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\System32\$sys$filesystem\aries.sys", string:winroot);

  # Connect to the appropriate share.
  name    =  kb_smb_name();
  port    =  kb_smb_transport();
  if (!get_port_state(port)) exit(1);
  login   =  kb_smb_login();
  pass    =  kb_smb_password();
  domain  =  kb_smb_domain();

  soc = open_sock_tcp(port);
  if (!soc) exit(1);

  session_init(socket:soc, hostname:name);
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1) {
    NetUseDel();
    exit(1, "cannot connect to the remote share");
  }

  # Try to open one of the driver's files.
  fh = CreateFile(
    file:file,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );

  # There's a problem if the file exists.
  if (!isnull(fh)) {
    security_warning(port);
    CloseFile(handle:fh);
  }
  NetUseDel();
}
