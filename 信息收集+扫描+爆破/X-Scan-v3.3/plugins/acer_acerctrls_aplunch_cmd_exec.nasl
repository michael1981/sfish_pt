#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40666);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2009-2627");
  script_bugtraq_id(36068);
  script_xref(name:"CERT", value:"485961");
  script_xref(name:"OSVDB", value:"57201");
  script_xref(name:"Secunia", value:"36343");

  script_name(english:"Acer AcerCtrls.APlunch ActiveX Arbitrary Command Execution");
  script_summary(english:"Checks for the ActiveX control");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote Windows host has an ActiveX control that allows arbitrary\n",
      "code execution."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The remote host contains an ActiveX control from Acer called\n",
      "'AcerCtrls.APlunch'.  If this control is distributed with the\n",
      "appropriate 'Implemented Categories' registry key, it may be marked\n",
      "as safe for scripting.  This would allow a web page in Internet\n",
      "Explorer to call the control's 'Run()' method.  A remote attacker\n",
      "could exploit this by tricking a user into visiting a malicious web\n",
      "page that executes arbitrary commands.\n",
      "\n",
      "Please note this vulnerability is similar to, but different from\n",
      "CVE-2006-6121.  This control has different parameters and uses a\n",
      "different CLSID."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kb.cert.org/vuls/id/485961"
  );
  script_set_attribute(
    attribute:"solution",
    value:string(
      "No patch is available at this time.  Disable this ActiveX control by\n",
      "setting the kill bit for the related CLSID.  Refer to the CERT\n",
      "advisory for more information."
    )
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009-08-18"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009-08-21"
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


if (!get_kb_item("SMB/Registry/Enumerated"))
  exit(1, "The 'SMB/Registry/Enumerated' KB item is missing");

# Locate the file used by the controls.
if (activex_init() != ACX_OK)
   exit(1, "activex_init() failed.");

clsid = "{3895DD35-7573-11D2-8FED-00606730D3AA}";
file = activex_get_filename(clsid:clsid);
if (!file)
{
  activex_end();
  exit(1, "Unable to get the filename of the control.");
}

# Acer hasn't released a patch yet.  All we can do for now is check to see
# if the killbit is set.
if (activex_get_killbit(clsid:clsid) != TRUE)
{
  if (report_verbosity > 0)
  {
    version = activex_get_fileversion(clsid:clsid);
    if (!version) version = "Unknown";

    report = string(
      "\n",
      "The killbit is not set for the following control :\n\n",
      "  Class Identifier : ", clsid, "\n",
      "  Filename         : ", file, "\n",
      "  Version          : ", version, "\n"
    );

    security_hole(port:kb_smb_transport(), extra:report);
  }
  else security_hole(port:kb_smb_transport());
  
  exit (0);
}
else exit(0, "The system is not affected.");

