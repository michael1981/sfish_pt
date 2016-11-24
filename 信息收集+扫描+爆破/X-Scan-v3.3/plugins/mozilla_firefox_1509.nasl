#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(23930);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2006-6497", "CVE-2006-6498", "CVE-2006-6499", "CVE-2006-6500", "CVE-2006-6501",
                "CVE-2006-6502", "CVE-2006-6503", "CVE-2006-6504", "CVE-2006-6506", "CVE-2006-6507");
  script_bugtraq_id(21668);
  script_xref(name:"OSVDB", value:"31339");
  script_xref(name:"OSVDB", value:"31340");
  script_xref(name:"OSVDB", value:"31341");
  script_xref(name:"OSVDB", value:"31342");
  script_xref(name:"OSVDB", value:"31343");
  script_xref(name:"OSVDB", value:"31344");
  script_xref(name:"OSVDB", value:"31345");
  script_xref(name:"OSVDB", value:"31346");
  script_xref(name:"OSVDB", value:"31347");
  script_xref(name:"OSVDB", value:"31348");

  script_name(english:"Firefox < 1.5.0.9 / 2.0.0.1 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The installed version of Firefox is affected by various security
issues, some of which may lead to execution of arbitrary code on the
affected host subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-68.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-69.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-70.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-71.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-72.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-73.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-75.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-76.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 1.5.0.9 / 2.0.0.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");
  exit(0);
}

#

include("misc_func.inc");

ver = read_version_in_kb("Mozilla/Firefox/Version");
if (isnull(ver)) exit(0);

if (
  ver[0] < 1 ||
  (
    ver[0] == 1 &&
    (
      ver[1] < 5 ||
      (ver[1] == 5 && ver[2] == 0 && ver[3] < 9)
    ) 
  ) ||
  (ver[0] == 2 && ver[1] == 0 && ver[2] == 0 && ver[3] < 1)
) security_hole(get_kb_item("SMB/transport"));
