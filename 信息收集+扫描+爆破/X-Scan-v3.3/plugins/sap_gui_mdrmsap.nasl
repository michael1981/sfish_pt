#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40617);
  script_version("$Revision: 1.1 $");

  script_cve_id("CVE-2008-4387");
  script_bugtraq_id(32186);
  script_xref(name:"OSVDB", value:"49721");

  script_name(english:"SAP SAPgui MDrmSap ActiveX (mdrmsap.dll) Buffer Overflow");
  script_summary(english:"Checks version of affected ActiveX control"); 

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote Windows host has an ActiveX control that is affected by a\n",
      "buffer overflow vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
     "The remote host contains the 'MDrmSap' ActiveX control included with\n",
      "SAP GUI version 6.40 for Windows.\n",
      "\n",
      "This control is reportedly affected by a buffer overflow involving\n",
      "instantiation by Internet Explorer.\n",
      "\n",
      "If an attacker can trick a user on the affected host into visiting a\n",
      "specially crafted web page, he may be able to leverage these issues to\n",
      "execute arbitrary code on the host subject to the user's privileges.\n",
      "\n",
      "The existence of this vulnerability is confirmed in mdrmsap.dll\n",
      "version 3.5.1.635.  Previous versions may also be affected."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.kb.cert.org/vuls/id/277313"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://service.sap.com/sap/support/notes/1142431 (login required)"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply the patch for the control as described in the vendor advisory."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/08/11"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/08/11"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/08/11"
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

if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "The 'SMB/Registry/Enumerated' KB item is missing.");
if (activex_init() != ACX_OK) exit(1, "activex_init() failed.");

# Locate the file used by the controls.
clsid = "{B01952B0-AF66-11D1-B10D-0060086F6D97}";

file = activex_get_filename(clsid:clsid);
if (file)
{
  version = activex_get_fileversion(clsid:clsid);
  if (!isnull(version)) version = "unknown";

  report = "";

  if (report_paranoia > 1)
    report = string(
      "\n",
      "  Class Identifier : ", clsid, "\n",
      "  Filename         : ", file, "\n",
      "  Version          : ", version, "\n",
      "\n",
      "Note, though, that Nessus did not check whether the 'kill' bit was \n",
      "set for the control's CLSID because the Report Paranoia setting \n",
      "was in effect when this scan was run.\n"
    );
  else if(activex_get_killbit(clsid:clsid) != TRUE)
    report = string(
      "\n",
      "  Class Identifier : ", clsid, "\n",
      "  Filename         : ", file, "\n",
      "  Version          : ", version, "\n",
      "\n",
      "Moreover, its 'kill' bit is not set so it is accessible via Internet\n",
      "Explorer.\n"
    );

  if (report)
  {
    if (report_verbosity > 0)
      security_hole(port:kb_smb_transport(), extra:report);
    else
      security_hole(kb_smb_transport());
  }
}
activex_end();
