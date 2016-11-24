#
#  (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(30152);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2008-0660", "CVE-2008-5711");
  script_bugtraq_id(27534, 27576, 27756);
  script_xref(name:"milw0rm", value:"5049");
  script_xref(name:"milw0rm", value:"5102");
  script_xref(name:"OSVDB", value:"41073");
  script_xref(name:"OSVDB", value:"41226");
  script_xref(name:"OSVDB", value:"41227");
  script_xref(name:"Secunia", value:"28713");

  script_name(english:"Facebook Photo Uploader ActiveX Control < 4.5.57.1 Multiple Buffer Overflows");
  script_summary(english:"Checks version of Facebook Photo Uploader ActiveX control"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by
multiple buffer overflow vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the Facebook Photo Uploader
ActiveX control that reportedly is affected by multiple buffer
overflows involving, for example, long arguments to the control's
'ExtractExif', 'ExtractIptc', and 'FileMask' properties.  If a remote
attacker can trick a user on the affected host into visiting a
specially-crafted web page, he may be able to leverage this issue to
execute arbitrary code on the affected host subject to the user's
privileges." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2008-02/0024.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Facebook Photo Uploader version 4.5.57.1 or later as it is
rumored to resolve the issues." );
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

#

include("global_settings.inc");
include("smb_func.inc");
include("smb_activex_func.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Locate the file used by the controls.
if (activex_init() != ACX_OK) exit(0);

clsid = "{5C6698D9-7BE4-4122-8EC5-291D84DBD4A0}";
file = activex_get_filename(clsid:clsid);
if (file)
{
  # Check its version.
  ver = activex_get_fileversion(clsid:clsid);
  if (ver && activex_check_fileversion(clsid:clsid, fix:"4.5.57.1") == TRUE)
  {
    report = NULL;
    if (report_paranoia > 1)
      report = string(
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
        "Version ", ver, " of the vulnerable control is installed as :\n",
        "\n",
        "  ", file, "\n",
        "\n",
        "Moreover, its 'kill' bit is not set so it is accessible via Internet\n",
        "Explorer.\n"
      );
    if (report)
    {
      if (report_verbosity) security_hole(port:kb_smb_transport(), extra:report);
      else security_hole(kb_smb_transport());
    }
  }
}
activex_end();
