#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40478);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2009-2404", "CVE-2009-2408", "CVE-2009-2654", "CVE-2009-2662",
                "CVE-2009-2663", "CVE-2009-2664");
  script_bugtraq_id(35803, 35888, 35891, 35927, 36018);
  script_xref(name:"OSVDB", value:"56717");
  script_xref(name:"OSVDB", value:"56719");
  script_xref(name:"OSVDB", value:"56720");
  script_xref(name:"OSVDB", value:"56721");
  script_xref(name:"OSVDB", value:"56722");
  script_xref(name:"OSVDB", value:"56724");
  script_xref(name:"Secunia", value:"36001");
  script_xref(name:"Secunia", value:"36088");

  script_name(english:"Firefox < 3.0.13 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote Windows host contains a web browser that is\n",
      "affected by multiple flaws."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The installed version of Firefox is earlier than 3.0.13.  Such\n",
      "versions are potentially affected by the following security issues :\n",
      "\n",
      "  - The browser can be fooled into trusting a malicious SSL\n",
      "    server certificate with a null character in the host name.\n",
      "    (MFSA 2009-42)\n",
      "\n",
      "  - A heap overflow in the code that handles regular\n",
      "    expressions in certificate names can lead to\n",
      "    arbitrary code execution. (MFSA 2009-43)\n",
      "\n",
      "  - The location bar and SSL indicators can be spoofed\n",
      "    by calling window.open() on an invalid URL. A remote\n",
      "    attacker could use this to perform a phishing attack.\n",
      "    (MFSA 2009-44)\n",
      "\n",
      "  - Unspecified JavaScript-related vulnerabilities can lead\n",
      "    to memory corruption, and possibly arbitrary execution\n",
      "    of code. (MFSA 2009-45)"
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-42.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-43.html"
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
    attribute:"solution",
    value:"Upgrade to Firefox 3.0.13 or later."
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

if (
  ver[0] < 3 ||
  (ver[0] == 3 && ver[1] == 0 && ver[2] < 13)
) security_hole(get_kb_item("SMB/transport"));
else exit(0, "No vulnerable versions of Firefox were found.");
