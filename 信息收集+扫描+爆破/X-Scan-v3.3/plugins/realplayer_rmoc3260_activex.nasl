#
#  (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(31418);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2008-1309");
  script_bugtraq_id(28157);
  script_xref(name:"OSVDB", value:"42946");
  script_xref(name:"Secunia", value:"29315");

  script_name(english:"RealPlayer ActiveX Control Heap Memory Corruption Vulnerabilities");
  script_summary(english:"Checks version of Real Player control");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by 
heap memory corruption vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host contains the Real Player ActiveX control, included
with the RealPlayer media player and used to play content in a
browser. 

The version of this control installed on the remote host reportedly
contains a buffer overflow that can be leveraged by calls to various
methods, such as 'Console', to modify heap blocks after they are freed
and overwrite certain registers.  If an attacker can trick a user on
the affected host into visiting a specially-crafted web page, he may
be able to use this method to execute arbitrary code on the affected
system subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2008-03/0157.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.kb.cert.org/vuls/id/831457" );
 script_set_attribute(attribute:"see_also", value:"http://service.real.com/realplayer/security/07252008_player/en/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to RealPlayer 11.0.3 (build 6.0.14.806) / RealPlayer 10.5
(build 6.0.12.1675) or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("realplayer_detect.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/RealPlayer/Product", "SMB/RealPlayer/Build", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("smb_func.inc");
include("smb_activex_func.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Determine based on the product's build number if it's potentially vulnerable.
prod = get_kb_item("SMB/RealPlayer/Product");
if (!prod) exit(0);


build = get_kb_item("SMB/RealPlayer/Build");
if (!build) exit(0);

ver = split(build, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);


vuln = FALSE;
if ("RealPlayer" == prod)
{
  # nb: build numbers ARE NOT NECESSARILY SEQUENTIAL!
  if (
    ver[0] < 6 ||
    (
      ver[0] == 6 && ver[1] == 0 && 
      (
        ver[2] < 12 ||
        (
          ver[2] == 12 && 
          (
            ver[3] <= 1663 ||
            ver[3] == 1698 ||
            ver[3] == 1741
          )
        ) ||
        (ver[2] == 14 && ver[3] < 806)
      )
    )
  ) vuln = TRUE;
}
else if ("RealPlayer Enterprise" == prod)
{
  vuln = TRUE;
}
if (!vuln) exit(0);


# Locate the file used by the controls.
if (activex_init() != ACX_OK) exit(0);

info = "";
clsids = make_list(
  "{0FDF6D6B-D672-463B-846E-C6FF49109662}",
  "{224E833B-2CC6-42D9-AE39-90B6A38A4FA2}",
  "{2F542A2E-EDC9-4BF7-8CB1-87C9919F7F93}",
  "{3B46067C-FD87-49B6-8DDD-12F0D687035F}",
  "{3B5E0503-DE28-4BE8-919C-76E0E894A3C2}",
  "{44CCBCEB-BA7E-4C99-A078-9F683832D493}",
  "{A1A41E11-91DB-4461-95CD-0C02327FD934}",
  "{CFCDAA03-8BE4-11CF-B84B-0020AFBBCCFA}"
);

foreach clsid (clsids)
{
  file = activex_get_filename(clsid:clsid);
  if (file)
  {
    # Check its version.
    ver = activex_get_fileversion(clsid:clsid);
    if (ver && activex_check_fileversion(clsid:clsid, fix:"6.0.10.50") == TRUE)
    {
      if (report_paranoia > 1 || activex_get_killbit(clsid:clsid) != TRUE)
      {
        info += '  ' + clsid + ',\n' + 
                '    ' + file + ' (' + ver + ')\n';
        if (!thorough_tests) break;
      }
    }
  }
}
activex_end();


if (info)
{
  info = string(
    "Nessus found the following affected control(s) :\n",
    "\n",
    info
  );
  if (report_paranoia > 1)
    report = string(
      "\n",
      info,
      "\n",
      "Note, though, that Nessus did not check whether the 'kill' bit was\n",
      "set for the control(s) because of the Report Paranoia setting in\n",
      "effect when this scan was run.\n"
    );
  else
    report = string(
      "\n",
      info,
      "\n",
      "Moreover, the 'kill' bit is not set for the control(s) so they are\n",
      "accessible via Internet Explorer.\n"
    );

  if (report_verbosity) security_hole(port:kb_smb_transport(), extra:report);
  else security_hole(kb_smb_transport());
}
