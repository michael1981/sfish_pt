#
#  (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(23932);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2006-6676", "CVE-2006-6677");
  script_bugtraq_id(21682, 21701);
  script_xref(name:"OSVDB", value:"32079");
  script_xref(name:"OSVDB", value:"32080");
  script_xref(name:"OSVDB", value:"32081");

  script_name(english:"NOD32 File Processing Vulnerabilities");
  script_summary(english:"Checks version of NOD32's virus signature database"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by
multiple issues." );
 script_set_attribute(attribute:"description", value:
"The version of NOD32 installed on the remote host reportedly has a
heap overflows involving processing of '.doc' and '.cab' files and a
divide-by-zero flaw involving '.chm' files.  A remote attacker may be
able to leverage the first flaw to execute code remotely or crash the
affected service." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2006-12/0357.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2006-12/0370.html" );
 script_set_attribute(attribute:"see_also", value:"http://eset.com/support/updates.php (look for 'v.1.1743 (20061215)')" );
 script_set_attribute(attribute:"solution", value:
"Run NOD32's Update feature an ensure the version of the virus
signature database is at least 1.1743." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("nod32_installed.nasl", "smb_hotfixes.nasl");
  script_require_keys("Antivirus/NOD32/installed", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


if (!get_kb_item("Antivirus/NOD32/installed")) exit(0);


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


# Get the version of the virus signature database.
ver = NULL;
key = "SOFTWARE\Eset\Nod\CurrentVersion\Info";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"CurrentVersion");
  if (!isnull(value))
  {
    ver = value[1];
    matches = eregmatch(string:ver, pattern:"^([0-9]+)\.([0-9]+) ");
    if (matches)
    {
      maj = int(matches[1]);
      min = int(matches[2]);
      if (
        maj == 0 ||
        (maj == 1 && min < 1743)
      )
      {
        report = desc + string(
          "\n\n",
          "Plugin output :\n",
          "\n",
          "The version of the virus signature database currently installed is : \n",
          "\n",
          "  ", ver, "\n"
        );
        security_hole(port:port, data:report);
      }
    }
  }

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
NetUseDel();
