#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(31733);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2008-1357");
  script_bugtraq_id(28228);
  script_xref(name:"OSVDB", value:"42853");
  script_xref(name:"Secunia", value:"29337");

  script_name(english:"McAfee Common Management Agent 3.6.0 UDP Packet Handling Format String (credentialed check)");
  script_summary(english:"Checks version of McAfee CMA");

 script_set_attribute(attribute:"synopsis", value:
"A remote service is affected by a format string vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a Common Management Agent, a component of
the ePolicy Orchestrator system security management solution from
McAfee. 

The version of the Common Management Agent on the remote host is
earlier than 3.6.0.595 and, as such, contains a format string
vulnerability.  If configured with a debug level of 8, its highest
level and not the default, an unauthenticated remote attacker may be
able to leverage this issue by sending a specially-crafted UDP packet
to the agent broadcast port to crash the service or even execute
arbitrary code on the affected host." );
 script_set_attribute(attribute:"see_also", value:"http://aluigi.altervista.org/adv/meccaffi-adv.txt" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/489476/100/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"https://knowledge.mcafee.com/article/234/615103_f.SAL_Public.html" );
 script_set_attribute(attribute:"solution", value:
"Apply Hotfix BZ398370 Build 595 for Common Management Agent 3.6.0
Patch 3." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );
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

key = "SOFTWARE\Network Associates\ePolicy Orchestrator\Agent";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"Installed Path");
  if (!isnull(value)) path = value[1];

  RegCloseKey(handle:key_h);
}
if (isnull(path))
{
  RegCloseKey(handle:hklm);
  NetUseDel();
  exit(0);
}


# Unless reporting is paranoid, don't worry if the log level is below 8.
loglevel = NULL;

if (report_paranoia < 2)
{
  key = "SOFTWARE\Network Associates\ePolicy Orchestrator";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:"LogLevel");
    if (!isnull(value)) loglevel = value[1];

    RegCloseKey(handle:key_h);
  }

  if (isnull(loglevel) || loglevel < 8)
  {
    RegCloseKey(handle:hklm);
    NetUseDel();
    exit(0);
  }
}
RegCloseKey(handle:hklm);


# Check the version of the exe.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\FrameworkService.exe", string:path);
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
  fix = split("3.6.0.595", sep:'.', keep:FALSE);
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
          "Version ", version, " of the McAfee Common Management Agent is installed\n",
          "under :\n",
          "\n",
          "  ", path, "\n"
        );

        if (report_paranoia > 1)
          report = string(
            report,
            "\n",
            "Note, though, that Nessus did not check the value of the debug level\n",
            "because of the Report Paranoia setting in effect when this scan was\n",
            "run.\n"
          );
        else
          report = string(
            report,
            "\n",
            "Moreover, Nessus has verified the debug level currently is set to ", loglevel, ".\n"
          );

        security_warning(port:port, extra:report);
      }
      else security_warning(port);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}
