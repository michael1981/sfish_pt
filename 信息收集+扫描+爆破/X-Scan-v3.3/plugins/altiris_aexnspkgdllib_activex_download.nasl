#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(41062);
  script_version("$Revision: 1.1 $");

  script_cve_id("CVE-2009-0328");
  script_bugtraq_id(36346);
  script_xref(name:"OSVDB", value:"57893");
  script_xref(name:"Secunia", value:"36679");

  script_name(english:"Altiris Altiris.AeXNSPkgDL.1 ActiveX Control DownloadAndInstall() Method Arbitrary Code Execution");
  script_summary(english:"Checks for the control");
 
  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote Windows host has an ActiveX control that allows execution\n",
      "of arbitrary code."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The Altiris.AeXNSPkgDL.1 ActiveX control, a component of Altiris\n",
      "Deployment Solution, Altiris Notification Server, and Symantec\n",
      "Management Platform, is installed on the remote Windows host.\n",
      "\n",
      "The installed version of this control provides an unsafe method, named\n",
      "'DownloadAndInstall'. \n",
      "\n",
      "If an attacker can trick a user on the affected host into viewing a\n",
      "specially crafted HTML document, he may be able to leverage this issue\n",
      "to download and execute arbitrary code on the affected system subject\n",
      "to the user's privileges."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.nessus.org/u?db53df37"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.nessus.org/u?01cdad31"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply the appropriate fix according to Symantec's advisory."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/09/09"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/09/23"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/09/23"
  );
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("smb_func.inc");
include("smb_activex_func.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "The 'SMB/Registry/Enumerated' KB item is missing.");


# Locate the file used by the controls.
if (activex_init() != ACX_OK) exit(1, "activex_init() failed.");

clsid = '{63716E93-033D-48B0-8A2F-8E8473FD7AC7}';
file = activex_get_filename(clsid:clsid);
if (file)
{
  version = activex_get_fileversion(clsid:clsid);
  if (!version) version = "unknown";

  report = "";
  if (report_paranoia > 1)
    report = string(
      "\n",
      "  Class Identifier : ", clsid, "\n",
      "  Filename         : ", file, "\n",
      "  Version          : ", version, "\n",
      "\n",
      "Note, though, that Nessus did not check whether the 'kill' bit was\n",
      "set for the control's CLSID because of the Report Paranoia setting\n",
      "in effect when this scan was run.\n"
    );
  else if (activex_get_killbit(clsid:clsid) != TRUE)
    report = string(
      "\n",
      "  Class Identifier : ", clsid, "\n",
      "  Filename         : ", file, "\n",
      "  Version          : ", version, "\n",
      "\n",
      "Moreover, its 'kill' bit is not set so it is accessible via Internet\n",
      "Explorer.\n"
    );
  if (report)
  {
    if (report_verbosity > 0) security_hole(port:kb_smb_transport(), extra:report);
    else security_hole(kb_smb_transport());
  }
}
activex_end();

if (file) exit(0);
else if (isnull(file)) exit(1, "activex_get_filename() failed.");
else if (strlen(file) == 0) exit(0, "The ActiveX control is not installed.");
