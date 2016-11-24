#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(31462);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2008-1471");
  script_bugtraq_id(28150);
  script_xref(name:"OSVDB", value:"42717");
  script_xref(name:"SECUNIA", value:"29311");

  script_name(english:"Panda Security cpoint.sys Kernel Memory Corruption");
  script_summary(english:"Checks version of Cpoint.sys");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by a kernel
memory corruption vulnerability." );
 script_set_attribute(attribute:"description", value:
"A vulnerability in the 'Cpoint.sys' kernel driver shipped with Panda
Antivirus+ Firewall 2008 and Panda Internet Security 2008 fails to
sufficiently validate IOCTL requests before processing them.  A local
attacker may be able to leverage this issue to execute arbitrary code
with kernel privileges or crash the system by causing a kernel panic." );
 script_set_attribute(attribute:"see_also", value:"http://www.trapkit.de/advisories/TKADV2008-001.txt" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2008-03/0106.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.pandasecurity.com/enterprise/support/card?id=41231" );
 script_set_attribute(attribute:"see_also", value:"http://www.pandasecurity.com/enterprise/support/card?id=41337" );
 script_set_attribute(attribute:"solution", value:
"Apply the appropriate hotfix as discussed in the vendor advisories
above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "panda_antivirus_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "Antivirus/Panda/installed");
  script_require_ports(139, 445);

  exit(0);
}


# Make sure Panda Antivirus is installed.
if (!get_kb_item("Antivirus/Panda/installed")) exit(0);


include("smb_func.inc");
include("smb_hotfixes.inc");

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

# Grab the file version of the affected file.
winroot = hotfix_get_systemroot();
if (!winroot) exit(1);

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:winroot);
sys =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\System32\drivers\cpoint.sys", string:winroot);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

fh = CreateFile(
  file:sys,
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
NetUseDel();


# Check the version number.
if (!isnull(ver))
{
  # Version of the driver after applying the hotfix
  fix = split("1.2.0.101", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      if (report_verbosity)
      {
	version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
        report = string(
          "\n",
          "Version ", version, " of the affected kernel driver is installed as :\n", 
          "\n",
          "  ", winroot, "\\System32\\drivers\\cpoint.sys\n"
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      break;
    }
    else if (ver[i] > fix[i])
      break;
} 
