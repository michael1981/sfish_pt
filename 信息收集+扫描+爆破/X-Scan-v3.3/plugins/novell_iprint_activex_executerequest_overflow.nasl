#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(31136);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2008-0935");
  script_bugtraq_id(27939);
  script_xref(name:"OSVDB", value:"42063");
  script_xref(name:"Secunia", value:"27994");

  script_name(english:"Novell iPrint Control ActiveX (ienipp.ocx) ExecuteRequest() Method Overflow");
  script_summary(english:"Checks version of iPrint Control ActiveX control"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by a
buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host contains the iPrint Control ActiveX control
distributed with Novell iPrint Client. 

The installed version of that control reportedly contains a buffer
overflow that can be triggered by passing an argument longer than 256
bytes to the 'ExecuteRequest' method.  If a remote attacker can trick
a user on the affected host into visiting a specially-crafted web
page, he may be able to leverage this issue to execute arbitrary code
on the affected host subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://download.novell.com/Download?buildid=prBBH4JpImA~" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Novell iPrint Client for Windows 4.34 or later and ensure
the control has a file version of 4.3.4.0 or higher." );
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


# Locate the file used by the controls.
if (activex_init() != ACX_OK) exit(0);

clsid = "{36723F97-7AA0-11D4-8919-FF2D71D0D32C}";
file = activex_get_filename(clsid:clsid);
if (file)
{
  # Check its version.
  ver = activex_get_fileversion(clsid:clsid);
  if (ver && activex_check_fileversion(clsid:clsid, fix:"4.3.4.0") == TRUE)
  {
    report = NULL;
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
    if (report)
    {
      if (report_verbosity) security_hole(port:kb_smb_transport(), extra:report);
      else security_hole(kb_smb_transport());
    }
  }
}
activex_end();
