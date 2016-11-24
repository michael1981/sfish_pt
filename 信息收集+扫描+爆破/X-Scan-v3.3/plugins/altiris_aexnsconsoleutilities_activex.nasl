#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42372);
  script_version("$Revision: 1.1 $");

  script_cve_id("CVE-2009-3031");
  script_bugtraq_id(36698);
  script_xref(name:"OSVDB", value:"59597");
  script_xref(name:"Secunia", value:"37229");

  script_name(english:"Altiris ConsoleUtilities ActiveX Control Buffer Overflow");
  script_summary(english:"Does a version check on AeXNSConsoleUtilities.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote Windows host has an ActiveX control with a buffer\n",
      "overflow vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "A vulnerable version of the Altiris ConsoleUtilities ActiveX control\n",
      "is installed on the remote host.  This control comes with Altiris\n",
      "Deployment Solution, Altiris Notification Server, and Symantec\n",
      "Management Platform.  There is a stack buffer overflow in the\n",
      "'BrowseAndSaveFile()' function.  A remote attacker could exploit this\n",
      "by tricking a user into requesting a maliciously crafted web page,\n",
      "which could lead to arbitrary code execution."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://archives.neohapsis.com/archives/fulldisclosure/2009-11/0011.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?292c32ff (Symantec advisory)"
  );
  script_set_attribute(
    attribute:"solution",
    value:string(
      "Remove all copies of the vulnerable control from this host, and\n",
      "apply the relevant hotfix referenced in the vendor's advisory."
    )
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/11/02"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/11/02"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/11/04"
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


clsid = '{B44D252D-98FC-4D5C-948C-BE868392A004}';
fixed_ver = '6.0.0.2000';
port = kb_smb_transport();

if (!get_kb_item("SMB/Registry/Enumerated"))
   exit(1, "The 'SMB/Registry/Enumerated' KB item is missing.");

if (activex_init() != ACX_OK) exit(1, "activex_init() failed.");

file = activex_get_filename(clsid:clsid);
if (file)
{
  version = activex_get_fileversion(clsid:clsid);

  if (!isnull(version) && activex_check_fileversion(clsid:clsid, fix:fixed_ver))
  {
    report = string(
      "\n",
      "  Class identifier  : ", clsid, "\n",
      "  Filename          : ", file, "\n",
      "  Installed version : ", version, "\n",
      "  Fixed version     : ", fixed_ver, "\n",
      "\n"
    );

    if (report_paranoia > 1)
    {
      report += string(
        "Note, though, that Nessus did not check whether the killbit was\n",
        "set for the control's CLSID because of the Report Paranoia setting\n",
        "in effect when this scan was run.\n"
      );
    }
    else
    {
      killbit = activex_get_killbit(clsid:clsid);
      report += string(
        "Moreover, its kill bit is not set so it is accessible via Internet\n",
        "Explorer.\n"
      );
    }

    # Only report if we're running as paranoid, or the kill bit isn't set
    if (report_paranoia > 1 || !killbit)
    {
      if (report_verbosity > 0)
        security_hole(port:port, extra:report);
      else
        security_hole(port);

      activex_end();
      exit(0);
    }
  }
}

activex_end();

if (isnull(file)) exit(1, "activex_get_filename() returned NULL.");
if (strlen(file) == 0) exit(0, "The control is not installed (class id '"+clsid+"' not found).");
if (isnull(version)) exit(1, "Failed to get file version of '"+file+"'.");
if (killbit) exit(0, file + " is vulnerable, but the kill bit is set.");
exit(0, "The control is not affected since its version is "+version+".");
