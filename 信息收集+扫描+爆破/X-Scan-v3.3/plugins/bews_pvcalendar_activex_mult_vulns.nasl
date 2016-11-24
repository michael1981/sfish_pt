#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(31351);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2007-6016", "CVE-2007-6017");
  script_bugtraq_id(26904, 28008);
  script_xref(name:"milw0rm", value:"5205");
  script_xref(name:"Secunia", value:"27885");
  script_xref(name:"OSVDB", value:"42358");
  script_xref(name:"OSVDB", value:"42360");

  script_name(english:"Symantec Backup Exec Calendar ActiveX Control Multiple Vulnerabilities (SYM08-007)");
  script_summary(english:"Checks version of Calendar ActiveX control"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host contains the PVATLCalendar.PVCalendar.1 ActiveX
control distributed with Symantec Backup Exec for Windows Servers. 

The installed version of that control reportedly contains two
stack-based buffer overflows and allows for corrupting or saving
malicious script code and overwriting arbitrary files.  These issues
can be triggered by specially-crafted arguments to the '_DOWText0'... 
'_DOWText6' and '_MonthText0' ... '_MonthText11' properties and then
calling the 'Save()' method." );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2007-101/advisory/" );
 script_set_attribute(attribute:"see_also", value:"http://www.symantec.com/avcenter/security/Content/2008.02.29.html" );
 script_set_attribute(attribute:"solution", value:
"Apply the appropriate hotfix as discussed in the vendor advisory
above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
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
include("smb_activex_func.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Check if the control looks like it's vulnerable.
if (activex_init() != ACX_OK) exit(0);

report = NULL;
clsid = "{22ACD16F-99EB-11D2-9BB3-00400561D975}";
file = activex_get_filename(clsid:clsid);
if (file)
{
  # Check its version.
  ver = activex_get_fileversion(clsid:clsid);
  if (ver && activex_check_fileversion(clsid:clsid, fix:"10.0.0.50") == TRUE)
  {
    if (report_paranoia > 1)
      report = string(
        "\n",
        "Version ", ver, " of the vulnerable control is installed as :\n",
        "\n",
        "  ", file, "\n",
        "\n",
        "Note, though, that Nessus did not check whether the 'kill' bit was\n",
        "set for the control's CLSID because of the Report Paranoia setting\n",
        "in effect when this scan was run.\n"
      );
    else if (activex_get_killbit(clsid:clsid) != TRUE)
      report = string(
        "\n",
        "Version ", ver, " of the vulnerable control is installed as :\n",
        "\n",
        "  ", file, "\n",
        "\n",
        "Moreover, its 'kill' bit is not set so it is accessible via Internet\n",
        "Explorer.\n"
      );
  }
}
activex_end();
if (isnull(report)) exit(0);



# NB: Symantec backported the patch with NetBackup so make sure we're looking at Backup Exec.
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
if (rc != 1) {
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


# Determine where Backup Exec is installed.
path = NULL;

key = "SOFTWARE\Symantec\Backup Exec for Windows\Backup Exec";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    if (strlen(subkey) && subkey =~ "^[0-9.]+$")
    {
      key2 = key + "\" + subkey + "\Install";
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        value = RegQueryValue(handle:key2_h, item:"Path");
        if (!isnull(value)) path = value[1];

        RegCloseKey(handle:key2_h);
      }
    }
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
NetUseDel();


# If it is installed, issue the report.
if (path)
{
  if (report_verbosity) security_hole(port:port, extra:report);
  else security_hole(port);
}
