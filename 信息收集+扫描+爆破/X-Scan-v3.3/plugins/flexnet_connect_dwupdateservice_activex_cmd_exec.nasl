#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25371);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2007-0328");
  script_bugtraq_id(24265);
  script_xref(name:"OSVDB", value:"36896");

  script_name(english:"Macrovision FLEXnet DWUpdateService ActiveX (agent.exe) Multiple Method Arbitrary Command Execution");
  script_summary(english:"Checks version of DWUpdateService ActiveX control"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that allows execution
of arbitrary commands." );
 script_set_attribute(attribute:"description", value:
"Macrovision FLEXnet Connect, formerly known as InstallShield Update
Service, is installed on the remote host.  It is a software management
solution for internally-developed and third-party applications, and
may have been installed as part of the FLEXnet Connect SDK, other
InstallShield software, or by running FLEXnet Connect-enabled Windows
software. 

The version of FLEXnet Connect on the remote host includes an ActiveX
control -- DWUpdateService -- that reportedly allows a remote,
unauthenticated attacker to execute arbitrary commands.  If an
attacker can trick a user on the affected host into visiting a
specially-crafted web page, he may be able to leverage this issue to
execute arbitrary code on the host subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.kb.cert.org/vuls/id/524681" );
 script_set_attribute(attribute:"see_also", value:"http://support.installshield.com/kb/view.asp?articleid=Q113020" );
 script_set_attribute(attribute:"solution", value:
"Either upgrade to a version of the FLEXnet Connect SDK with installer
version 12.0.0.49974 or later or disable the control as described in
the US-CERT advisory referenced above." );
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


# Locate the file used by the controls.
if (activex_init() != ACX_OK) exit(0);

clsid = '{551E5190-19C7-4626-9D54-FB20355E6467}';
file = activex_get_filename(clsid:clsid);
if (file)
{
  # Check its version.
  ver = activex_get_fileversion(clsid:clsid);
  if (ver && activex_check_fileversion(clsid:clsid, fix:"6.0.100.60146") == TRUE)
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
    if (report) security_hole(port:kb_smb_transport(), extra:report);
  }
}
activex_end();
