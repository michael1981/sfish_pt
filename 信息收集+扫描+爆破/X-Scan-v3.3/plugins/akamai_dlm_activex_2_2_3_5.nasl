#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(32082);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2007-6339");
  script_bugtraq_id(28993);
  script_xref(name:"OSVDB", value:"44882");
  script_xref(name:"Secunia", value:"30037");

  script_name(english:"Akamai Download Manager ActiveX Control < 2.2.3.5 Remote Code Execution");
  script_summary(english:"Checks version of Download Manager ActiveX control"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that allows remote code
execution." );
 script_set_attribute(attribute:"description", value:
"The Windows remote host contains the Download Manager ActiveX control
from Akamai, which helps users download content. 

The version of this ActiveX control on the remote host reportedly
allows downloading and automatic execution of arbitrary code.  If an
attacker can trick a user on the affected host into visiting a
specially-crafted web page, he may be able to use this method to
execute arbitrary code on the affected system subject to the user's
privileges." );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=695" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2008-05/0002.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2008-04/0813.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 2.2.3.5 or later of the control." );
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

# Locate the file used by the control.
if (activex_init() != ACX_OK) 
  exit(1, "ActiveX initialization failed.");

clsids = make_list("{FFBB3F3B-0A5A-4106-BE53-DFE1E2340CB1}",
                   "{2AF5BD25-90C5-4EEC-88C5-B44DC2905D8B}");

info = NULL;
foreach clsid (clsids)
{
 file = activex_get_filename(clsid:clsid);

 if (file)
 {
   # Check its version.
   ver = activex_get_fileversion(clsid:clsid);

   # Fixed version of DownloadManagerV2.ocx == 2.2.3.5
   if (ver && activex_check_fileversion(clsid:clsid, fix:"2.2.3.5") == TRUE)
    {
      if (report_paranoia > 1 || activex_get_killbit(clsid:clsid) != TRUE)
       {
        info += '  - ' + clsid + '\n' +
                '    ' + file + ', ' + ver + '\n';

        if (!thorough_tests) break;
       } 
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
     	"\n",
    	info,
      	"\n",
        "Note that Nessus did not check whether the 'kill' bit was set for\n",
        "the control(s) because of the Report Paranoia setting in effect\n",
        "when this scan was run.\n"
      );
    }
    else
    {
      report = string(
        "\n",
        "Nessus found the following affected control(s) installed :\n",
        "\n",
        info,
        "\n",
        "Moreover, the 'kill' bit was  not set for the control(s) so they\n",
        "are accessible via Internet Explorer.\n"
      );
    }
    security_hole(port:kb_smb_transport(), extra:report);
  }	  	 
  else security_hole(kb_smb_transport());
} 
