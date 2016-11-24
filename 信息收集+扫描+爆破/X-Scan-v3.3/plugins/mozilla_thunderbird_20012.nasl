#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(31193);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2008-0304", "CVE-2008-0412", "CVE-2008-0413",
                "CVE-2008-0415", "CVE-2008-0416", "CVE-2008-0418");
  script_bugtraq_id(27406, 27683, 28012, 29303);
  script_xref(name:"OSVDB", value:"41187");
  script_xref(name:"OSVDB", value:"41220");
  script_xref(name:"OSVDB", value:"41222");
  script_xref(name:"OSVDB", value:"41223");
  script_xref(name:"OSVDB", value:"42056");
  script_xref(name:"OSVDB", value:"42428");
  script_xref(name:"OSVDB", value:"43456");
  script_xref(name:"OSVDB", value:"43457");
  script_xref(name:"OSVDB", value:"43458");
  script_xref(name:"OSVDB", value:"43459");
  script_xref(name:"OSVDB", value:"43460");
  script_xref(name:"OSVDB", value:"43461");
  script_xref(name:"OSVDB", value:"43462");

  script_name(english:"Mozilla Thunderbird < 2.0.0.12 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Thunderbird");
 
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
      "The installed version of Thunderbird is affected by various security\n",
      "issues :\n\n",
      "  - Several stability bugs leading to crashes which, in\n",
      "    some cases, show traces of memory corruption.\n\n",
      "  - Several issues that allow scripts from page content\n",
      "    to escape from their sandboxed context and/or run\n",
      "    with chrome privileges, resulting in privilege\n",
      "    escalation, XSS, and/or remote code execution.\n\n",
      "  - A directory traversal vulnerability via the\n",
      "    'chrome:' URI.\n\n",
      "  - A heap buffer overflow that can be triggered\n",
      "    when viewing an email with an external MIME\n",
      "    body.\n\n",
      "  - Multiple cross-site scripting vulnerabilities\n",
      "    related to character encoding."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-01.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-03.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-05.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-12.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-13.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Mozilla Thunderbird 2.0.0.12 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");
  exit(0);
}

#

include("misc_func.inc");

ver = read_version_in_kb("Mozilla/Thunderbird/Version");
if (isnull(ver)) exit(0);

if (
  ver[0] < 2 ||
  (ver[0] == 2 && ver[1] == 0 && ver[2] == 0 && ver[3] < 12)
) security_hole(get_kb_item("SMB/transport"));
