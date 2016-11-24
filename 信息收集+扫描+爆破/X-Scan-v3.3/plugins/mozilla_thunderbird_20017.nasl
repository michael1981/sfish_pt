#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(34294);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2008-0016", "CVE-2008-3835", "CVE-2008-4058", "CVE-2008-4059",
                "CVE-2008-4060", "CVE-2008-4061", "CVE-2008-4062", "CVE-2008-4063",
                "CVE-2008-4064", "CVE-2008-4065", "CVE-2008-4066", "CVE-2008-4067",
                "CVE-2008-4068", "CVE-2008-4070");
  script_bugtraq_id(31346, 31411);
  script_xref(name:"OSVDB", value:"48746");
  script_xref(name:"OSVDB", value:"48747");
  script_xref(name:"OSVDB", value:"48748");
  script_xref(name:"OSVDB", value:"48749");
  script_xref(name:"OSVDB", value:"48750");
  script_xref(name:"OSVDB", value:"48751");
  script_xref(name:"OSVDB", value:"48759");
  script_xref(name:"OSVDB", value:"48760");
  script_xref(name:"OSVDB", value:"48761");
  script_xref(name:"OSVDB", value:"48762");
  script_xref(name:"OSVDB", value:"48763");
  script_xref(name:"OSVDB", value:"48764");
  script_xref(name:"OSVDB", value:"48765");
  script_xref(name:"OSVDB", value:"48766");
  script_xref(name:"OSVDB", value:"48767");
  script_xref(name:"OSVDB", value:"48768");
  script_xref(name:"OSVDB", value:"48769");
  script_xref(name:"OSVDB", value:"48770");
  script_xref(name:"OSVDB", value:"48771");
  script_xref(name:"OSVDB", value:"48772");
  script_xref(name:"OSVDB", value:"48773");
  script_xref(name:"OSVDB", value:"48780");
  script_xref(name:"Secunia", value:"32007");

  script_name(english:"Mozilla Thunderbird < 2.0.0.17 Multiple Vulnerabilities");
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
      "issues :\n",
      "\n",
      "  - Using a specially crafted UTF-8 URL in a hyperlink, an\n",
      "    attacker might be able to exploit a stack buffer\n",
      "    overflow in the Mozilla URL parsing routes to execute\n",
      "    arbitrary code (MFSA 2008-37).\n",
      "\n",
      "  - It is possible to bypass the same-origin check in\n",
      "    'nsXMLDocument::OnChannelRedirect()' (MFSA 2008-38).\n",
      "\n",
      "  - Privilege escalation is possible via 'XPCnativeWrapper'\n",
      "    pollution (MFSA 2008-41).\n",
      "\n",
      "  - There are several stability bugs in the browser engine\n",
      "    that may lead to crashes with evidence of memory\n",
      "    corruption (MFSA 2008-42).\n",
      "\n",
      "  - Certain BOM characters and low surrogate characters,\n",
      "    if HTML-escaped, are stripped from JavaScript code\n",
      "    before it is executed, which could allow for cross-\n",
      "    site scripting attacks (MFSA 2008-43).\n",
      "\n",
      "  - The 'resource:' protocol allows directory traversal\n",
      "    on Linux when using URL-encoded slashes, and it can\n",
      "    by used to bypass restrictions on local HTML files\n",
      "    (MFSA 2008-44).\n",
      "\n",
      "  - There is a heap buffer overflow that can be triggered\n",
      "    when canceling a newsgroup message (MFSA 2008-46)."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-37.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-38.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-41.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-42.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-43.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-44.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-46.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Mozilla Thunderbird 2.0.0.17 or later."
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
  (ver[0] == 2 && ver[1] == 0 && ver[2] == 0 && ver[3] < 17)
) security_hole(get_kb_item("SMB/transport"));
