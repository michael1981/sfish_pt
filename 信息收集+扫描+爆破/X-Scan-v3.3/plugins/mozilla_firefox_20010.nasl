#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(28329);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2007-5947", "CVE-2007-5959", "CVE-2007-5960");
  script_bugtraq_id(26385, 26589, 26593);
  script_xref(name:"OSVDB", value:"38463");
  script_xref(name:"OSVDB", value:"38867");
  script_xref(name:"OSVDB", value:"38868");

  script_name(english:"Firefox < 2.0.0.10 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The installed version of Firefox is affected by various security
issues :

  - Three bugs that can result in crashes with traces 
    of memory corruption

  - A cross-site scripting vulnerability involving
    support for the 'jar:' URI scheme

  - A timing issue when setting the 'window.location' 
    property that could be leveraged to conduct
    cross-site request forgery attacks." );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-37.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-38.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-39.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 2.0.0.10 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");
  exit(0);
}

#

include("misc_func.inc");

ver = read_version_in_kb("Mozilla/Firefox/Version");
if (isnull(ver)) exit(0);

if (
  ver[0] < 2 ||
  (ver[0] == 2 && ver[1] == 0 && ver[2] == 0 && ver[3] < 10)
) security_hole(get_kb_item("SMB/transport"));
