#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");
if ( NASL_LEVEL < 3000 ) exit(0);


if (description)
{
  script_id(42116);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2009-0901", "CVE-2009-2493", "CVE-2009-2495");
  script_bugtraq_id(35828, 35830, 35832);
  script_xref(name:"OSVDB", value:"56696");
  script_xref(name:"OSVDB", value:"56698");
  script_xref(name:"OSVDB", value:"56699");

  script_name(english:"MS09-060: Vulnerabilities in Microsoft Active Template Library (ATL) ActiveX Controls for Microsoft Office Could Allow Remote Code Execution (973965)");
  script_summary(english:"Checks version of various files");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "Arbitrary code can be executed on the remote host through Microsoft\n",
      "Office ActiveX controls."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "One or more ActiveX controls included in Microsoft Outlook or Visio\n",
      "and installed on the remote Windows host was compiled with a version\n",
      "of Microsoft Active Template Library (ATL) that is affected by\n",
      "potentially several vulnerabilities :\n",
      "\n",
      "  - An issue in the ATL headers could allow an attacker to\n",
      "    force VariantClear to be called on a VARIANT that has\n",
      "    not been correctly initialized and, by supplying a\n",
      "    corrupt stream, to execute arbitrary code.\n",
      "    (CVE-2009-0901)\n",
      "\n",
      "  - Unsafe usage of 'OleLoadFromStream' could allow\n",
      "    instantiation of arbitrary objects which can bypass\n",
      "    related security policy, such as kill bits within\n",
      "    Internet Explorer. (CVE-2009-2493)\n",
      "\n",
      "  - An attacker who is able to run a malicious component or\n",
      "    control built using Visual Studio ATL can, by\n",
      "    manipulating a string with no terminating NULL byte, \n",
      "    read extra data beyond the end of the string and thus \n",
      "    disclose information in memory. (CVE-2009-2495)"
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Microsoft has released a set of patches for Microsoft Outlook 2002,\n",
      "2003, and 2007 as well as Visio Viewer 2007 :\n",
      "\n",
      "http://www.microsoft.com/technet/security/Bulletin/MS09-060.mspx"
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/07/28"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/10/13"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/10/14"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}



include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


if (!get_kb_item("SMB/WindowsVersion")) exit(1, "The 'SMB/WindowsVersion' KB item is missing.");
if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "The 'SMB/Registry/Enumerated' KB item is missing.");

# Determine the install path for Vision Viewer 2007.
visio_viewer_path = NULL;

name    =  kb_smb_name();
port    =  kb_smb_transport();
if (!get_port_state(port)) exit(0);
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

soc = open_sock_tcp(port);
if (!soc) exit(1, "Can't open a socket on port "+port+".");

session_init(socket:soc, hostname:name);
hcf_init = TRUE;
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to IPC$ share.");
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Can't connect to remote registry.");
}

key = "SOFTWARE\Microsoft\Office";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"InstallRoot");
  if (value) visio_viewer_path = value[1];

  RegCloseKey(handle:key_h);
}
if (isnull(visio_viewer_path))
{
  key = "SOFTWARE\Microsoft\Office\12.0\Common\InstallRoot";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:"Path");
    if (value) visio_viewer_path = value[1];

    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);


vuln = 0;


# Office
outlook_path = get_kb_item("SMB/Office/Outlook/Path");
if (outlook_path)
{
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:outlook_path);
  if (!is_accessible_share(share:share)) exit(1, "Can't access '"+share+"' share.");

  if (
    # Outlook 2007
    hotfix_check_fversion(path:outlook_path, file:"Outlmime.dll", version:"12.0.6514.5000", min_version:"12.0.0.0") == HCF_OLDER ||

    # Outlook 2003
    hotfix_check_fversion(path:outlook_path, file:"Outllib.dll", version:"11.0.8313.0", min_version:"11.0.0.0") == HCF_OLDER ||

    # Outlook 2002
    hotfix_check_fversion(path:outlook_path, file:"Outllib.dll", version:"10.0.6856.0", min_version:"10.0.0.0") == HCF_OLDER
  ) vuln++;
}


# Visio
#
# - Visio Viewer 2007.
if (visio_viewer_path)
{
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:visio_viewer_path);
  if (!is_accessible_share(share:share)) exit(1, "Can't access '"+share+"' share.");

  if (
    hotfix_check_fversion(path:visio_viewer_path, file:"Vpreview.exe", version:"12.0.6513.5000", min_version:"12.0.0.0") == HCF_OLDER ||
    hotfix_check_fversion(path:visio_viewer_path, file:"Vviewdwg.dll", version:"12.0.6500.5000", min_version:"12.0.0.0") == HCF_OLDER ||
    hotfix_check_fversion(path:visio_viewer_path, file:"vviewer.dll",  version:"12.0.6513.5000", min_version:"12.0.0.0") == HCF_OLDER
  ) vuln++;
}
# - nb: we don't check for Visio Viewer 2002 and 2003 because the 
#       vulnerabilities are mitigated by applying MS09-034, and we
#       do have a check for that.


if (vuln)
{
  set_kb_item(name:"SMB/Missing/MS09-060", value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end(); 
  exit(0);
}
else
{
  hotfix_check_fversion_end(); 
  exit(0, "The host is not affected.");
}
