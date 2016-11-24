#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(35287);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2008-5500", "CVE-2008-5503", "CVE-2008-5506", "CVE-2008-5507",
                "CVE-2008-5508", "CVE-2008-5510", "CVE-2008-5511", "CVE-2008-5512");
  script_bugtraq_id(32882);
  script_xref(name:"OSVDB", value:"51284");
  script_xref(name:"OSVDB", value:"51285");
  script_xref(name:"OSVDB", value:"51288");
  script_xref(name:"OSVDB", value:"51291");
  script_xref(name:"OSVDB", value:"51292");
  script_xref(name:"OSVDB", value:"51293");
  script_xref(name:"OSVDB", value:"51294");
  script_xref(name:"OSVDB", value:"51295");
  script_xref(name:"OSVDB", value:"51296");

  script_name(english:"Mozilla Thunderbird < 2.0.0.19 Multiple Vulnerabilities");
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
      "The installed version of Thunderbird is earlier than 2.0.0.19.  Such\n",
      "versions are potentially affected by the following security issues :\n",
      "\n",
      "  - There are several stability bugs in the browser engine\n",
      "    that may lead to crashes with evidence of memory\n",
      "    corruption. (MFSA 2008-60)\n",
      "\n",
      "  - XBL bindings can be used to read data from other\n",
      "    domains. (MFSA 2008-61)\n",
      "\n",
      "  - Sensitive data may be disclosed in an XHR response when\n",
      "    an XMLHttpRequest is made to a same-origin resource,\n",
      "    which 302 redirects to a resource in a different\n",
      "    domain. (MFSA 2008-64)\n",
      "\n",
      "  - A website may be able to access a limited amount of\n",
      "    data from a different domain by loading a same-domain\n",
      "    JavaScript URL which redirects to an off-domain target\n",
      "    resource containing data which is not parsable as\n",
      "    JavaScript. (MFSA 2008-65)\n",
      "\n",
      "  - Errors arise when parsing URLs with leading whitespace\n",
      "    and control characters. (MFSA 2008-66)\n",
      "\n",
      "  - An escaped null byte is ignored by the CSS parser and\n",
      "    treated as if it was not present in the CSS input\n",
      "    string. (MFSA 2008-67)\n",
      "\n",
      "  - XSS and JavaScript privilege escalation are possible.\n",
      "    (MFSA 2008-68)"
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-60.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-61.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-64.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-65.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-66.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-67.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-68.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.com/en-US/thunderbird/2.0.0.19/releasenotes/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Mozilla Thunderbird 2.0.0.19 or later."
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
  script_require_keys("Mozilla/Thunderbird/Version");

  exit(0);
}


include("misc_func.inc");


ver = read_version_in_kb("Mozilla/Thunderbird/Version");
if (isnull(ver)) exit(0);

if (
  ver[0] < 2 ||
  (ver[0] == 2 && ver[1] == 0 && ver[2] == 0 && ver[3] < 19)
) security_hole(get_kb_item("SMB/transport"));
