#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(21188);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2006-1693");
  script_bugtraq_id(17398);
  script_xref(name:"OSVDB", value:"24451");

  script_name(english:"GlobalSCAPE Secure FTP Server (gsftps) Custom Command Long Parameter DoS");
  script_summary(english:"Checks version of GlobalSCAPE Secure FTP"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is prone to denial of service attacks." );
 script_set_attribute(attribute:"description", value:
"GlobalSCAPE Secure FTP Server is installed on the remote Windows host. 

According to the registry, the version of GlobalSCAPE Secure FTP
Server on the remote host is affected by a denial of service
vulnerability involving a lengthy parameter line to an unspecified
custom command." );
 script_set_attribute(attribute:"see_also", value:"http://www.globalscape.com/gsftps/history.asp" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to GlobalSCAPE Secure FTP Server 3.1.4 Build 01.10.2006 or
later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
  script_dependencies("ftpserver_detect_type_nd_version.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports("Services/ftp", 21, 139, 445);

  exit(0);
}


include("ftp_func.inc");
include("global_settings.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(1);

# Get the version number from the registry.
key = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/{C680402D-A6CD-11D5-804F-00010246ECC0}/DisplayVersion";
ver = get_kb_item(key);


# If it looks vulnerable...
if (ver && ver =~ "^([0-2]\.|3\.(0\.|1\.[0-3]))") 
{
  # Make sure it's running.
  port = get_kb_item("Services/ftp");
  if (!port) port = 21;
  if (!get_port_state(port)) exit(0);

  # Unless we're paranoid...
  if (report_paranoia < 2)
  {
    # Make sure the banner says it's GlobalSCAPE.
    banner = get_ftp_banner(port:port);
    if (!banner || "GlobalSCAPE Secure FTP Server" >!< banner) exit(0);
  }

  security_warning(port);
}
