#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(30202);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2008-0437");
  script_bugtraq_id(27384);
  script_xref(name:"OSVDB", value:"40890");

  script_name(english:"HP Virtual Rooms WebHPVCInstall.HPVirtualRooms14 ActiveX Control Buffer Overflow Vulnerabilities");
  script_summary(english:"Checks version of WebHPVCInstall.HPVirtualRooms14 ActiveX control"); 
 
  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote Windows host has an ActiveX control that is affected by\n",
      "multiple buffer overflow vulnerabilities."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote host contains a version of the HP Virtual Rooms\n",
      "WebHPVCInstall.HPVirtualRooms14 ActiveX control that reportedly is\n",
      "affected by multiple buffer overflows involving properties such as\n",
      "'AuthenticationURL', 'PortalAPIURL', and 'cabroot'.  If a remote\n",
      "attacker can trick a user on the affected host into visiting a\n",
      "specially-crafted web page, he may be able to leverage this issue to\n",
      "execute arbitrary code on the affected host subject to the user's\n",
      "privileges."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://archives.neohapsis.com/archives/fulldisclosure/2008-01/0461.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/archive/1/487654"
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Upgrade to HP Virtual Rooms v7 or use the HPVR removal tool referenced\n",
      "in the vendor advisory above to remove the software."
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );
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

info = "";
for (i=31; i>=0; i--)
{
  zeros = crap(data:"0", length:8-strlen(string(i)));
  clsid = string("{", zeros, i, "-9593-4264-8B29-930B3E4EDCCD}");

  file = activex_get_filename(clsid:clsid);
  if (file)
  {
    if (
      report_paranoia > 1 ||
      activex_get_killbit(clsid:clsid) != TRUE
    )
    {
      info += '  ' + file + '\n';
      if (!thorough_tests) break;
    }
  }
}
activex_end();


if (info)
{
  report = string(
    "\n",
    "Nessus found the following affected control(s) installed :\n",
    "\n",
    info
  );

  if (!thorough_tests)
  {
    report = string(
      report,
      "\n",
      "Note that Nessus did not check whether there were other instances\n",
      "installed because the Thorough Tests setting was not enabled when\n",
      "this scan was run.\n"
    );
  }

  if (report_paranoia > 1)
    report = string(
      report,
      "\n",
      "Note that Nessus did not check whether the 'kill' bit was set for\n",
      "the control(s) because of the Report Paranoia setting in effect\n",
      "when this scan was run.\n"
    );
  else 
    report = string(
      report,
      "\n",
      "Moreover, the 'kill' bit was  not set for the control(s) so they\n",
      "are accessible via Internet Explorer.\n"
    );
  if (report_verbosity) security_hole(port:kb_smb_transport(), extra:report);
  else security_hole(kb_smb_transport());
}
