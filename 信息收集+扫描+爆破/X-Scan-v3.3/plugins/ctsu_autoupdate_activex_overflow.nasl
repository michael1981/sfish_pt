#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(32442);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2008-0955");
  script_bugtraq_id(29391);
  script_xref(name:"milw0rm", value:"5681");
  script_xref(name:"Secunia", value:"30403");
  script_xref(name:"OSVDB", value:"45655");

  script_name(english:"Creative Software AutoUpdate Engine ActiveX (CTSUEng.ocx) Unspecified Overflow");
  script_summary(english:"Checks version of Creative Software AutoUpdate Engine control");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by a
buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host contains the Creative Software AutoUpdate Engine
ActiveX control, which is used to automatically update Creative Labs
software. 

The version of this control installed on the remote host reportedly
contains an unspecified stack buffer overflow.  If an attacker can
trick a user on the affected host into viewing a specially-crafted
HTML document, he may be able to use this method to execute arbitrary
code on the affected system subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://research.eeye.com/html/alerts/zeroday/20080526.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.kb.cert.org/vuls/id/501843" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
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

clsid = "{0A5FD7C5-A45C-49FC-ADB5-9952547D5715}";
file = activex_get_filename(clsid:clsid);
if (file)
{
  ver = activex_get_fileversion(clsid:clsid);
  if (ver) ver = string("Version ", ver);
  else ver = string("An unknown version");

  report = NULL;
  if (report_paranoia > 1)
    report = string(
      "\n",
      ver, " of the vulnerable control is installed as :\n",
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
      ver, " of the vulnerable control is installed as :\n",
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
activex_end();
