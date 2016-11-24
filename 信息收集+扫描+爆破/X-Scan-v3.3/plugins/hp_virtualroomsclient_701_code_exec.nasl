#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(35804);
  script_version("$Revision: 1.1 $");
  
  script_cve_id("CVE-2009-0208");
  script_bugtraq_id(33918);

  script_name(english:"HP Virtual Rooms Client < 7.0.1 ActiveX Control Dangerous Methods");
  script_summary(english:"Checks vulnerable clsids");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that fails to restrict
access to dangerous methods." );

 script_set_attribute(attribute:"description", value:
"HP Virtual Rooms client is installed on the remote system.  An ActiveX
control included with the client and provided by a file with a name
such as 'HPVirtualRooms32.dll' contains several dangerous methods.  By
tricking a user into viewing a specially crafted HTML document, it may
be possible for an attacker to use these methods and execute arbitrary
code on the remote system subject to the user's privileges.");

 script_set_attribute(attribute:"see_also", value:
"http://www.kb.cert.org/vuls/id/461321" );
 script_set_attribute(attribute:"see_also", value:
"http://archives.neohapsis.com/archives/bugtraq/2009-02/0227.html" );

 script_set_attribute(attribute:"solution", value:
"Upgrade to HP Virtual Rooms client version 7.0.1." );
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

info = "";
for (i=32; i>=0; i--)
{
  zeros = crap(data:"0", length:8-strlen(string(i)));
  clsid = string("{", zeros, i, "-9593-4264-8B29-930B3E4EDCCD}");

  file = activex_get_filename(clsid:clsid);
  if (file)
  { 
    ver = activex_get_fileversion(clsid:clsid);
    if (!ver) ver = "unknown";

    if (report_paranoia > 1 || activex_get_killbit(clsid:clsid) != TRUE)
    { 
      info += '\n' +
              '  CLSID   : ' + clsid + '\n' +
              '  File    : ' + file + '\n' +
              '  Version : ' + version + '\n';
        
      if (!thorough_tests) break;
    }
  }
}

activex_end();

if (info)
{ 
  if (report_verbosity > 0)
  { 
    if (report_paranoia > 1)
    { 
      report = string(
        "\n",
        "Nessus found the following affected control(s) installed :\n",
        # nb: info already starts with an empty line.
        info,
        "\n",
        "Note, though, that Nessus did not check whether the 'kill' bit was\n",
        "set for the control's CLSID because of the Report Paranoia setting\n",
        "in effect when this scan was run.\n"
      );
    }
    else
    {
      report = string(
        "\n",
        "Nessus found the following affected control(s) installed :\n",
        # nb: info already starts with an empty line.
        info,
        "\n",
        "Moreover, the 'kill' bit is not set so it is accessible via Internet\n",
        "Explorer.\n"
      );
    }
    security_hole(port:kb_smb_transport(), extra:report);
  }
  else security_hole(kb_smb_transport());
}
