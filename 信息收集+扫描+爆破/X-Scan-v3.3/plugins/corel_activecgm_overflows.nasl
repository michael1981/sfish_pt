#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25494);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2007-2921");
  script_bugtraq_id(24464);
  script_xref(name:"OSVDB", value:"35468");

  script_name(english:"Corel ActiveCGM Browser ActiveX (acqm.dll) Multiple Overflows");
  script_summary(english:"Checks versions of ActiveCGM ActiveX control"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is susceptible to
multiple buffer overflow attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host contains the ActiveCGM ActiveX control, which supports
viewing of CGM files in a web browser. 

The version of this control on the remote host is reportedly affected
by multiple buffer overflows.  If an attacker can trick a user on the
affected host into visiting a specially-crafted web page, he may be
able to leverage these issues to execute arbitrary code on the host
subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.kb.cert.org/vuls/id/983249" );
 script_set_attribute(attribute:"solution", value:
"Either disable the use of this ActiveX control from within Internet
Explorer by setting its 'kill' bit or contact the vendor to upgrade it
to version 7.1.4.19 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("smb_func.inc");
include("smb_activex_func.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Locate files used by the controls.
if (activex_init() != ACX_OK) exit(0);

clsid = "{F5D98C43-DB16-11cf-8ECA-0000C0FD59C7}";
file = activex_get_filename(clsid:clsid);
if (file)
{
  ver = activex_get_fileversion(clsid:clsid);
  if (ver && activex_check_fileversion(clsid:clsid, fix:"7.1.4.19") == TRUE)
  {
    report = NULL;
    if (report_paranoia > 1)
      report = string(
        "According to the registry, version '", ver, "' of the vulnerable\n",
        "control is installed as :\n",
        "\n",
        "  ", file, "\n",
        "\n",
        "Note, though, that Nessus did not check whether the 'kill' bit was\n",
        "set for the control's CLSID because of the Report Paranoia setting\n",
        "in effect when this scan was run.\n"
      );
    else if (activex_get_killbit(clsid:clsid) != TRUE)
      report = string(
        "According to the registry, version '", ver, "' of the vulnerable\n",
        "control is installed as :\n",
        "\n",
        "  ", file, "\n",
        "\n",
        "Moreover, its 'kill' bit is not set so it is accessible via\n",
        "Internet Explorer."
      );
    if (report) security_hole(port:kb_smb_transport(), extra:report);
  }
}
activex_end();
