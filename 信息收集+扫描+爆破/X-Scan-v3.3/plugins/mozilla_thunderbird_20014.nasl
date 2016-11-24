#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(32134);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2008-1233", "CVE-2008-1234", "CVE-2008-1235", 
                "CVE-2008-1236", "CVE-2008-1237");
  script_xref(name:"OSVDB", value:"43857");
  script_xref(name:"OSVDB", value:"43858");
  script_xref(name:"OSVDB", value:"43859");
  script_xref(name:"OSVDB", value:"43860");
  script_xref(name:"OSVDB", value:"43861");
  script_xref(name:"OSVDB", value:"43862");
  script_xref(name:"OSVDB", value:"43863");
  script_xref(name:"OSVDB", value:"43864");
  script_xref(name:"OSVDB", value:"43865");
  script_xref(name:"OSVDB", value:"43866");
  script_xref(name:"OSVDB", value:"43867");
  script_xref(name:"OSVDB", value:"43868");
  script_xref(name:"OSVDB", value:"43869");
  script_xref(name:"OSVDB", value:"43870");
  script_xref(name:"OSVDB", value:"43871");
  script_xref(name:"OSVDB", value:"43872");
  script_xref(name:"OSVDB", value:"43873");
  script_xref(name:"OSVDB", value:"43874");
  script_xref(name:"OSVDB", value:"43875");
  script_xref(name:"OSVDB", value:"43876");
  script_xref(name:"OSVDB", value:"43877");
  script_xref(name:"OSVDB", value:"43878");

  script_name(english:"Mozilla Thunderbird < 2.0.0.14 Multiple Vulnerabilities");
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
      "  - A series of vulnerabilities that allow for JavaScript\n",
      "    privilege escalation and arbitrary code execution.\n\n",
      "  - Several stability bugs leading to crashes which, in\n",
      "    some cases, show traces of memory corruption."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-14.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-15.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Mozilla Thunderbird 2.0.0.14 or later."
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
  (ver[0] == 2 && ver[1] == 0 && ver[2] == 0 && ver[3] < 14)
) security_hole(get_kb_item("SMB/transport"));
