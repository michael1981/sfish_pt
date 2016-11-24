#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(36162);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2008-5731", "CVE-2009-0681");	
  script_bugtraq_id(32991, 34490);
  script_xref(name:"OSVDB", value:"50914");
  script_xref(name:"OSVDB", value:"53678");
  script_xref(name:"OSVDB", value:"53679");
	
  script_name(english:"PGP Desktop < 9.10 Multiple Local DoS");
  script_summary(english:"Checks version of pgpdisk.sys"); 
 
  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by multiple
vulnerabilities." );
  script_set_attribute(attribute:"description", value:
"PGP Desktop is installed on the remote system.  The installed version
is older than 9.10, and such versions are reportedly affected by the
following issues :

  - The IOCTL handler in 'pgpdisk.sys' fails to perform 
    sufficient boundary checks on data associated with 'Irp'
    objects. A local attacker can exploit this flaw to crash 
    the system.

  - The IOCTL handler in 'pgpwded.sys' fails to perform 
    sufficient boundary checks on data associated with 'Irp'
    objects. A local attacker can exploit this flaw to crash 
    the system or execute arbitrary code with SYSTEM 
    privileges." );
  script_set_attribute(attribute:"see_also", value:"http://en.securitylab.ru/lab/PT-2009-01" );
  script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2009-04/0121.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8403a1c7 (PGP Desktop 9.10 - Resolved Issues)" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to PGP Desktop version 9.10, which reportedly addresses these
issues." );

  script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C" );
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");

# Get the install path

name    =  kb_smb_name();
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if (!get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (!soc) exit(0);

session_init(socket:soc, hostname:name);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

winroot = hotfix_get_systemroot();
if (!winroot) exit(1);

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:winroot);
sys =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\system32\drivers\pgpdisk.sys", string:winroot);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
 NetUseDel();
 exit(0);
}

fh = CreateFile(file:sys, 
	desired_access:GENERIC_READ, 
	file_attributes:FILE_ATTRIBUTE_NORMAL, 
	share_mode:FILE_SHARE_READ, 
	create_disposition:OPEN_EXISTING);

ver = NULL;

if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}
NetUseDel();

# Check the version number.
if (!isnull(ver))
{
  # Version of the driver that is not vulnerable
  fix = split("9.10", sep:'.', keep:FALSE);
  for (i=0; i < max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i < max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      if (report_verbosity > 0 )
      {
	version = string(ver[0], ".", ver[1], ".", ver[2]);
        report = string(
          "\n",
          "Version ", version, " of the affected driver is installed as :\n", 
          "\n",
          "  ", winroot, "\\system32\\drivers\\pgpdisk.sys\n"
        );
        security_warning(port:port, extra:report);
      }
      else security_warning(port);
      break;
    }
    else if (ver[i] > fix[i])
      break;
} 
