#
#  (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25459);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2007-3147", "CVE-2007-3148");
  script_bugtraq_id(24354, 24355);
  script_xref(name:"OSVDB", value:"37081");
  script_xref(name:"OSVDB", value:"37082");

  script_name(english:"Yahoo! Messenger Webcam ActiveX Buffer Overflow Vulnerabilities");
  script_summary(english:"Checks versions of Webcam ActiveX controls"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a least one ActiveX control that is
affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host contains the 'Webcam' ActiveX controls included with
Yahoo! Messenger. 

The version of at least one of these controls on the remote host has a
buffer overflow.  If an attacker can trick a user on the affected host
into visiting a specially-crafted web page, he may be able to leverage
these issues to execute arbitrary code on the host subject to the
user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2007-06/0131.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2007-06/0133.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/470861/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://messenger.yahoo.com/security_update.php?id=060707" );
 script_set_attribute(attribute:"solution", value:
"Update to the latest version of Yahoo! Messenger and ensure that the
version of both affected controls is 2.0.1.6 or higher." );
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

info = "";
clsids = make_list(
  "{DCE2F8B1-A520-11D4-8FD0-00D0B7730277}",
  "{9D39223E-AE8E-11D4-8FD3-00D0B7730277}"
);
foreach clsid (clsids)
{
  file = activex_get_filename(clsid:clsid);
  if (file)
  {
    ver = activex_get_fileversion(clsid:clsid);
    if (ver && activex_check_fileversion(clsid:clsid, fix:"2.0.1.6") == TRUE)
    {
      info += '  ' + file + ' (' + ver + ')\n';
      if (!thorough_tests) break;
    }
  }
}
activex_end();


if (info)
{
  report = string(
    "Nessus found the following affected control(s) installed :\n",
    "\n",
    info
  );
  security_hole(port:kb_smb_transport(), extra: report);
}
