#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(34348);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2008-4453");
  script_bugtraq_id(31504);
  script_xref(name:"milw0rm", value:"6638");
  script_xref(name:"OSVDB", value:"48656");
  script_xref(name:"OSVDB", value:"48657");
  script_xref(name:"Secunia", value:"31966");
  script_xref(name:"Secunia", value:"31898");

  script_name(english:"GdPicture Multiple ActiveX Control SaveAsPDF Method Arbitrary File Overwrite");
  script_summary(english:"Checks version of GdPicture control");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that allows overwriting
arbitrary files." );
 script_set_attribute(attribute:"description", value:
"The remote host contains the GdPicturePro5S.Imaging or
GdPicture4S.Imaging ActiveX control, which is used to manipulate
images in a variety of formats. 

The version of the control installed on the remote host reportedly
fails to validate input to the 'sFilePath' argument of the 'SaveAsPDF'
method.  If an attacker can trick a user on the affected host into
viewing a specially-crafted HTML document, he may be able to use this
method to create or overwrite arbitrary files on the affected system
subject to the user's privileges, which could in turn lead to
execution of arbitrary code." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b0052882" );
 script_set_attribute(attribute:"see_also", value:"http://www.forums.gdpicture.com/post3101.html#p3101" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to GdPicture Light Imaging Toolkit 4.7.2 (with version 4.7.0.2
of the control) / GdPicture Pro Imaging SDK 5.7.2 (with version
5.7.0.2 of the control) or later." );
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

clsid = '{E8512363-3581-42EF-A43D-990E7935C8BE}';
file = activex_get_filename(clsid:clsid);
if (file)
{
  ver = activex_get_fileversion(clsid:clsid);

  if (ver =~ "^5\.") fix = "5.7.0.2";
  else if (ver =~ "^4\.") fix = "4.7.0.2";
  else fix = "";

  if (ver && fix && activex_check_fileversion(clsid:clsid, fix:fix) == TRUE)
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
