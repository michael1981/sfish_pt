#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(25350);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2007-1558", "CVE-2007-2867", "CVE-2007-2868");
  script_bugtraq_id(23257, 24242);
  script_xref(name:"OSVDB", value:"34856");
  script_xref(name:"OSVDB", value:"35134");
  script_xref(name:"OSVDB", value:"35138");

  script_name(english:"Mozilla Thunderbird < 1.5.0.12 Multiple Vulnerabilities");
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
      "security issues, at least one that may lead to execution of arbitrary\n",
      "code on the affected host subject to the user's privileges."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-12.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-15.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Mozilla Thunderbird 1.5.0.12 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
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
      (ver[1] == 5 && ver[2] == 0 && ver[3] < 12)
    )
  )
) security_hole(get_kb_item("SMB/transport"));
