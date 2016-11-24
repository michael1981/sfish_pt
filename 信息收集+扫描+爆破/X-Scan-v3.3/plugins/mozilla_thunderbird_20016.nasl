#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(33563);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2008-2798", "CVE-2008-2799", "CVE-2008-2802", "CVE-2008-2803",
                "CVE-2008-2807", "CVE-2008-2809", "CVE-2008-2811", "CVE-2008-2785");
  script_bugtraq_id(29802, 30038);
  script_xref(name:"OSVDB", value:"46421");
  script_xref(name:"OSVDB", value:"46673");
  script_xref(name:"OSVDB", value:"46674");
  script_xref(name:"OSVDB", value:"46675");
  script_xref(name:"OSVDB", value:"46677");
  script_xref(name:"OSVDB", value:"46679");
  script_xref(name:"OSVDB", value:"46682");
  script_xref(name:"OSVDB", value:"46683");
  script_xref(name:"Secunia", value:"30915");

  script_name(english:"Mozilla Thunderbird < 2.0.0.16 Multiple Vulnerabilities");
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
      "  - Several stability bugs leading to crashes which, in\n",
      "    some cases, show traces of memory corruption\n",
      "    (MFSA 2008-21).\n",
      "\n",
      "  - By taking advantage of the privilege level stored in\n",
      "    the pre-compiled 'fastload' file. an attacker may be\n",
      "    able to run arbitrary JavaScript code with chrome\n",
      "    privileges (MFSA 2008-24).\n",
      "\n",
      "  - Arbitrary code execution is possible in\n",
      "    'mozIJSSubScriptLoader.loadSubScript()' (MFSA 2008-25).\n",
      "\n",
      "  - Several function calls in the MIME handling code\n",
      "    use unsafe versions of string routines (MFSA 2008-26).\n",
      "\n",
      "  - An improperly encoded '.properties' file in an add-on\n",
      "    can result in uninitialized memory being used, which\n",
      "    could lead to data formerly used by other programs\n",
      "    being exposed to the add-on code (MFSA 2008-29).\n",
      "\n",
      "  - A weakness in the trust model regarding alt names on\n",
      "    peer-trusted certs could lead to spoofing secure\n",
      "    connections to any other site (MFSA 2008-31).\n",
      "\n",
      "  - A crash in Mozilla's block reflow code could be used\n",
      "    by an attacker to crash the browser and run arbitrary\n",
      "    code on the victim's computer (MFSA 2008-33).\n",
      "\n",
      "  - By creating a very large number of references to a\n",
      "    common CSS object, an attacker can overflow the CSS\n",
      "    reference counter, causing a crash when the browser\n",
      "    attempts to free the CSS object while still in use\n",
      "    and allowing for arbitrary code execution\n",
      "    (MFSA 2008-34)."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-21.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-24.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-25.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-26.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-29.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-31.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-33.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-34.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Mozilla Thunderbird 2.0.0.16 or later."
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
  (ver[0] == 2 && ver[1] == 0 && ver[2] == 0 && ver[3] < 16)
) security_hole(get_kb_item("SMB/transport"));
