#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(35403);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2008-4388");
  script_bugtraq_id(33247);
  script_xref(name:"OSVDB", value:"51410");
  script_xref(name:"Secunia", value:"33582");

  script_name(english:"Symantec AppStream Client LaunchObj ActiveX Control Multiple Unsafe Methods (SYM09-001)");
  script_summary(english:"Checks version of LaunchObj control");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that can be used to
download and execute arbitrary code." );
 script_set_attribute(attribute:"description", value:
"The version of the LaunchObj ActiveX control, a component included
with Symantec AppStream Client / Altiris Streaming Agent and installed
on the remote Windows host, reportedly contains a number of unsafe
methods, such as 'installAppMgr()', that can be used to download and
execute arbitrary code.  If an attacker can trick a user on the
affected host into viewing a specially crafted HTML document, he can
leverage these issues to execute arbitrary code on the affected system
subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.kb.cert.org/vuls/id/194505" );
 script_set_attribute(attribute:"see_also", value:"http://www.symantec.com/avcenter/security/Content/2009.01.15.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec AppStream Client 5.2.2 SP3 MP1 or later and verify
that the version of the control is 5.2.2.865 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
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


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Locate the file used by the controls.
if (activex_init() != ACX_OK) exit(0);

clsid = '{3356DB7C-58A7-11D4-AA5C-006097314BF8}';
file = activex_get_filename(clsid:clsid);
if (file)
{
  ver = activex_get_fileversion(clsid:clsid);

  if (ver && activex_check_fileversion(clsid:clsid, fix:"5.2.2.865") == TRUE)
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
