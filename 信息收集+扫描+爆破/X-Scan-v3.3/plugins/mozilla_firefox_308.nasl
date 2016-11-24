#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(36045);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2009-1044", "CVE-2009-1169");
  script_bugtraq_id(34181, 34235);
  script_xref(name:"OSVDB", value:"52896");
  script_xref(name:"OSVDB", value:"53079");

  script_name(english:"Firefox < 3.0.8 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote Windows host contains a web browser that is affected by\n",
      "multiple vulnerabilities."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The installed version of Firefox is earlier than 3.0.8.  Such versions\n",
      "are potentially affected by the following security issues :\n",
      "\n",
      "  - An XSL transformation vulnerability can be leveraged \n",
      "    with a specially crafted stylesheet to crash the browser\n",
      "    or to execute arbitrary code. (MFSA 2009-12)\n",
      "\n",
      "  - An error in the XUL tree method '_moveToEdgeShift()' can\n",
      "    be leveraged to trigger garbage collection routines on\n",
      "    objects that are still in use, leading to a browser\n",
      "    crash and possibly execution of arbitrary code. \n",
      "    (MFSA 2009-13)\n"
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-12.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-13.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.mozilla.com/en-US/firefox/3.0.8/releasenotes/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Firefox 3.0.8 or later. "
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
 
  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}


include("misc_func.inc");


ver = read_version_in_kb("Mozilla/Firefox/Version");
if (isnull(ver)) exit(0);

if (
  ver[0] < 3 ||
  (ver[0] == 3 && ver[1] == 0 && ver[2] < 8)
) security_hole(get_kb_item("SMB/transport"));
