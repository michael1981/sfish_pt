#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40479);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2009-2654", "CVE-2009-2470", "CVE-2009-2662", "CVE-2009-2663", "CVE-2009-2664",
                "CVE-2009-2665", "CVE-2009-3071", "CVE-2009-3075");
  script_bugtraq_id(35803, 35925, 35927, 35928, 36018, 36343);
  script_xref(name:"OSVDB", value:"56716");
  script_xref(name:"OSVDB", value:"56717");
  script_xref(name:"OSVDB", value:"56718");
  script_xref(name:"OSVDB", value:"56719");
  script_xref(name:"OSVDB", value:"56720");
  script_xref(name:"OSVDB", value:"56721");
  script_xref(name:"OSVDB", value:"56722");
  script_xref(name:"OSVDB", value:"57976");
  script_xref(name:"OSVDB", value:"57973");
  script_xref(name:"Secunia", value:"36001");

  script_name(english:"Firefox < 3.5.2 Multiple Vulnerabilities");
  script_summary(english:"Checks version number");

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
      "The installed version of Firefox is earlier than 3.5.2.  Such versions\n",
      "are potentially affected by the following security issues :\n",
      "\n",
      "  - A SOCKS5 proxy that replies with a hostname containing\n",
      "    more than 15 characters can corrupt the subsequent\n",
      "    data stream.  This can lead to a denial of service,\n",
      "    though there is reportedly no memory corruption.\n",
      "    (MFSA 2009-38)\n",
      "\n",
      "  - The location bar and SSL indicators can be spoofed\n",
      "    by calling window.open() on an invalid URL. A remote\n",
      "    attacker could use this to perform a phishing attack.\n",
      "    (MFSA 2009-44)\n",
      "\n",
      "  - Unspecified JavaScript-related vulnerabilities can lead\n",
      "    to memory corruption, and possibly arbitrary execution\n",
      "    of code. (MFSA 2009-45, MFSA 2009-47)\n",
      "\n",
      "  - If an add-on has a 'Link:' HTTP header when it is installed,\n",
      "    the window's global object receives an incorrect security\n",
      "    wrapper, which could lead to arbitrary JavaScript being\n",
      "    executed with chrome privileges. (MFSA 2009-46)"
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-38.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-44.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-45.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-46.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-47.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Firefox 3.5.2 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/08/04"
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

# Only checks the 3.5.x branch
if (ver[0] == 3 && ver[1] == 5 && ver[2] < 2)
  security_hole(get_kb_item("SMB/transport"));
else exit(0, "No vulnerable versions of Firefox were found.");
