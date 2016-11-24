#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40931);
  script_version("$Revision: 1.3 $");
  script_cve_id(
    "CVE-2009-3069",
    "CVE-2009-3072",
    "CVE-2009-3073",
    "CVE-2009-3077",
    "CVE-2009-3078",
    "CVE-2009-3079"
  );
  script_bugtraq_id(36343);
  script_xref(name:"OSVDB", value:"57970");
  script_xref(name:"OSVDB", value:"57972");
  script_xref(name:"OSVDB", value:"57974");
  script_xref(name:"OSVDB", value:"57978");
  script_xref(name:"OSVDB", value:"57979");
  script_xref(name:"OSVDB", value:"57980");
  script_xref(name:"Secunia", value:"36671");

  script_name(english:"Firefox < 3.5.3 Multiple Vulnerabilities");
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
      "The installed version of Firefox is earlier than 3.5.3.  Such\n",
      "versions are potentially affected by the following security issues :\n",
      "\n",
      "  - Multiple memory corruption vulnerabilities could potentially\n",
      "    allow arbitrary code execution. (MFSA 2009-47)\n",
      "\n",
      "  - The columns of a XUL tree element can manipulated in\n",
      "    a way that leads to a dangling pointer.  A remote attacker\n",
      "    could exploit this to crash the browser, or execute\n",
      "    arbitrary code. (MFSA 2009-49)\n",
      "\n",
      "  - A URL containing certain Unicode characters with tall\n",
      "    tall-line height is displayed incorrectly in the location bar.\n",
      "    A remote attacker could use this to prevent a user from\n",
      "    seeing the full URL of a malicious web site. (MFSA 2009-50)\n",
      "\n",
      "  - A remote attacker can leverage 'BrowserFeedWriter' to\n",
      "    execute JavaScript code with Chrome privileges.\n",
      "    (MFSA 2009-51)"
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-47.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-49.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-50.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-51.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Firefox 3.5.3 or later"
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/09/09"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/09/09"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/09/10"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");
  exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");

ver = read_version_in_kb("Mozilla/Firefox/Version");
if (isnull(ver)) exit(1, "The 'Mozilla/Firefox/Version' KB item is missing.");

# only checks the 3.5.x branch
if (ver[0] == 3 && ver[1] == 5 && ver[2] < 3)
  security_hole(get_kb_item("SMB/transport"));
else
  exit(0, "No vulnerable versions of Firefox were found.");

