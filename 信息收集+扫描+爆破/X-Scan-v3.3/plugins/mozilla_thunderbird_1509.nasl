#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(23929);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2006-6497", "CVE-2006-6498", "CVE-2006-6499", "CVE-2006-6500",
                "CVE-2006-6501", "CVE-2006-6502", "CVE-2006-6503", "CVE-2006-6504",
                "CVE-2006-6505");
  script_bugtraq_id(21668);
  script_xref(name:"OSVDB", value:"31341");
  script_xref(name:"OSVDB", value:"31342");
  script_xref(name:"OSVDB", value:"31343");
  script_xref(name:"OSVDB", value:"31344");
  script_xref(name:"OSVDB", value:"31345");
  script_xref(name:"OSVDB", value:"31346");
  script_xref(name:"OSVDB", value:"31348");
  script_xref(name:"OSVDB", value:"31349");
  script_xref(name:"OSVDB", value:"31350");

  script_name(english:"Mozilla Thunderbird < 1.5.0.9 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Mozilla Thunderbird");
 
  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote Windows host contains a mail client that is affected by\n",
      "multiple vulnerabilities."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote version of Mozilla Thunderbird suffers from various\n",
      "security issues, at least one of which may lead to execution of\n",
      "arbitrary code on the affected host."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-68.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-69.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-70.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-71.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-72.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-73.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-74.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Mozilla Thunderbird 1.5.0.9 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");
  exit(0);
}

#

include("misc_func.inc");

ver = read_version_in_kb("Mozilla/Thunderbird/Version");
if (isnull(ver)) exit(0);

if (
  ver[0] < 1 ||
  (
    ver[0] == 1 &&
    (
      ver[1] < 5 ||
      (ver[1] == 5 && ver[2] == 0 && ver[3] < 9)
    )
  )
) security_hole(get_kb_item("SMB/transport"));
