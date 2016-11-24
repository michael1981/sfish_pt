#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(33108);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2008-2541");
  script_bugtraq_id(29528);
  script_xref(name:"OSVDB", value:"46012");
  script_xref(name:"OSVDB", value:"46013");
  script_xref(name:"Secunia", value:"30518");

  script_name(english:"CA Secure Content Manager HTTP Gateway Service FTP Vulnerabilities");
  script_summary(english:"Checks registry for SCM's PatchID key"); 

 script_set_attribute(attribute:"synopsis", value:
"A remote Windows host contains a program that is affected by multiple
buffer overflow vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Computer Associates' Secure Content
Manager, a gateway product for filtering messaging and web traffic. 

The HTTP Gateway component ('icihttp.exe') of the version of Secure
Content Manager installed on the remote host does not sufficiently
check responses to FTP 'LIST' and 'PASV' commands before copying them
into a stack buffer.  An unauthenticated remote attacker can leverage
these issues to crash the affected service or to execute arbitrary
code on the affected host with SYSTEM privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-035/" );
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-036/" );
 script_set_attribute(attribute:"see_also", value:"http://dvlabs.tippingpoint.com/advisory/TPTI-08-05" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2008-06/0041.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2008-06/0042.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2008-06/0043.html" );
 script_set_attribute(attribute:"see_also", value:"https://support.ca.com/irj/portal/anonymous/phpsupcontent?contentID=177784" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/493124/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Apply the QO99987 patch referenced in the CA advisory." );
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


# Determine if SCM r8 is installed and identify which patches have been applied.
base_key = "SOFTWARE\ComputerAssociates\eTrust\SCM\8.0";
path = NULL;
patches = NULL;

key = base_key + "\Directories";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"InstallRoot");
  if (!isnull(value))
  {
    path = value[1];
    path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
  }
  RegCloseKey(handle:key_h);
}
if (!isnull(path))
{
  key = base_key + "\Hidden";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:"PatchID");
    if (!isnull(value)) patches = value[1];

    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0);
}


# There's a problem if there are no patches or "80VULNHOTFIX" is not one of them.
if (strlen(patches) == 0 || "|80VULNHOTFIX|" >!< patches)
{
  if (report_verbosity)
  {
    if ("|" >< patches)
    {
      if (patches[0] == "|") patches = substr(patches, 1);
      if (patches[strlen(patches)-1] == "|") patches = substr(patches, 0, strlen(patches)-2);
      patches = str_replace(find:"|", replace:", ", string:patches);
    }
    else if (strlen(patches) == 0) patches = "none";

    report = string(
      "\n",
      "Nessus collected the following information about the installation of CA\n",
      "Secure Content Manager r8 on the remote host :\n",
      "\n",
      "   Path      : ", path, "\n",
      "   Patch(es) : ", patches, "\n"
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
