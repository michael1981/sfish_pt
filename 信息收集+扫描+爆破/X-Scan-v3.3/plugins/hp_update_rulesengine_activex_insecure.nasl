#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(29747);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2007-6506");
  script_bugtraq_id(26950);
  script_xref(name:"OSVDB", value:"40237");
  script_xref(name:"OSVDB", value:"40238");

  script_name(english:"HP Software Update HPRulesEngine.ContentCollection ActiveX (RulesEngine.dll) Multiple Insecure Methods");
  script_summary(english:"Checks whether kill-bit is set for HP Rules Processing Engine ActiveX control"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that allows reading and
writing of arbitrary files." );
 script_set_attribute(attribute:"description", value:
"The remote host contains the HP Software Update software, installed by
default on many HP notebooks to support automatic software updates and
vulnerability patching. 

The version of this software on the remote host includes an ActiveX
control, 'RulesEngineLib', that reportedly contains two insecure
methods - 'LoadDataFromFile()' and 'SaveToFile()' - that are marked as
'Safe for Scripting' and allow for reading and overwriting arbitrary
files on the affected system.  If a remote attacker can trick a user
on the affected host into visiting a specially-crafted web page, he
may be able to leverage this issue to effectively destroy arbitrary
files on the remote host, potentially even files that are vital for
its operation, or to read the contents of arbitrary files." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/485325/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/13673" );
 script_set_attribute(attribute:"solution", value:
"Either use HP Software Update itself to update the software or disable
use of this ActiveX control from within Internet Explorer by setting
its 'kill' bit." );
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


include("smb_func.inc");
include("smb_activex_func.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Locate the file used by the controls.
if (activex_init() != ACX_OK) exit(0);

clsid = "{7CB9D4F5-C492-42A4-93B1-3F7D6946470D}";
file = activex_get_filename(clsid:clsid);
if (file)
{
  report = NULL;
  if (activex_get_killbit(clsid:clsid) != TRUE)
    report = string(
      "\n",
      "The vulnerable control is installed as :\n",
      "\n",
      "  ", file, "\n",
      "\n",
      "Moreover, its 'kill' bit is not set so it is accessible via Internet\n",
      "Explorer.\n"
    );
  if (report) security_hole(port:kb_smb_transport(), extra:report);
}
activex_end();
