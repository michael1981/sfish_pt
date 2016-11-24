#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(32081);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2008-2214");
  script_bugtraq_id(28990);
  script_xref(name:"Secunia", value:"30036");
  script_xref(name:"OSVDB", value:"44885");

  script_name(english:"SNMPc < 7.1.1 UDP Packet Handling Buffer Overflow");
  script_summary(english:"Checks version of SNMPc's crserv.exe"); 

 script_set_attribute(attribute:"synopsis", value:
"A remote Windows host contains a program that is affected by a buffer
overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running SNMPc, a network management application for
Windows from Castle Rock Computing. 

The version of SNMPc installed on the remote host reportedly is
affected by a stack buffer overflow vulnerability.  Using a specially-
crafted SNMP TRAP packet with an overly long community string, an
unauthenticated remote attacker can able to leverage this issue to
execute arbitrary code on the remote host with LocalSystem privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.ngssoftware.com/advisories/critical-vulnerability-in-snmpc/" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/491454" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to SNMPc version 7.1.1 or later as that reportedly resolves
the issue." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

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


# Determine where it's installed.
path = NULL;

key = "SOFTWARE\Castle Rock Computing\SNMPc Network Manager";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"Dir");
  if (!isnull(value)) path = value[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  RegCloseKey(handle:hklm);
  NetUseDel();
  exit(0);
}

# Check the version of the SNMPc Server exe.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\crserv.exe", string:path);
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
  fix = split("7.1.1", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      if (report_verbosity)
      {
        # nb: only the first 3 parts seem to be reported to end-users.
        version = string(ver[0], ".", ver[1], ".", ver[2]);

        report = string(
          "\n",
          "SNMPc's Management Server version ", version, " is installed under :\n",
          "\n",
          "  ", path, "\n"
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}
