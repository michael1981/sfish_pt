#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(27521);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2007-1095", "CVE-2007-2292", "CVE-2006-2894", "CVE-2007-3511", "CVE-2007-4841",
                "CVE-2007-5334", "CVE-2007-5337", "CVE-2007-5338", "CVE-2007-5339", "CVE-2007-5340",
                "CVE-2007-5691");
  script_bugtraq_id(18308, 22688, 23668, 24725, 25543, 26132, 26159);
  script_xref(name:"OSVDB", value:"26178");
  script_xref(name:"OSVDB", value:"33809");
  script_xref(name:"OSVDB", value:"37994");
  script_xref(name:"OSVDB", value:"37995");
  script_xref(name:"OSVDB", value:"38030");
  script_xref(name:"OSVDB", value:"38033");
  script_xref(name:"OSVDB", value:"38034");
  script_xref(name:"OSVDB", value:"38035");
  script_xref(name:"OSVDB", value:"38043");
  script_xref(name:"OSVDB", value:"38044");
  script_xref(name:"OSVDB", value:"43609");

  script_name(english:"Firefox < 2.0.0.8 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The installed version of Firefox is affected by various security
issues, some of which may lead to execution of arbitrary code on the
affected host subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-29.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-30.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-31.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-32.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-33.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-34.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-35.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-36.html" );
 script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=388424" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 2.0.0.8 or later." );
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
  (ver[0] == 2 && ver[1] == 0 && ver[2] == 0 && ver[3] < 8)
) security_hole(get_kb_item("SMB/transport"));
