#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(29743);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2007-5339", "CVE-2007-5340");
  script_bugtraq_id(26132);
  script_xref(name:"OSVDB", value:"38043");
  script_xref(name:"OSVDB", value:"38044");

  script_name(english:"Mozilla Thunderbird < 1.5.0.14 Multiple Vulnerabilities");
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
      "security issues, several of which may lead to execution of arbitrary\n",
      "code on the affected host subject to the user's privileges."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-29.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-40.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Mozilla Thunderbird 1.5.0.14 or later."
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
      (ver[1] == 5 && ver[2] == 0 && ver[3] < 14)
    )
  )
) security_hole(get_kb_item("SMB/transport"));
