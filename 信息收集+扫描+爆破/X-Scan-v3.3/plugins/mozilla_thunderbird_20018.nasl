#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(34819);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2008-5012", "CVE-2008-5014", "CVE-2008-5016", "CVE-2008-5017",
                "CVE-2008-5018", "CVE-2008-5021", "CVE-2008-5022", "CVE-2008-5024",
                "CVE-2008-5052", "CVE-2008-6961");
  script_bugtraq_id(32281, 32351, 32363);
  script_xref(name:"OSVDB", value:"49995");
  script_xref(name:"OSVDB", value:"50139");
  script_xref(name:"OSVDB", value:"50141");
  script_xref(name:"OSVDB", value:"50176");
  script_xref(name:"OSVDB", value:"50177");
  script_xref(name:"OSVDB", value:"50179");
  script_xref(name:"OSVDB", value:"50181");
  script_xref(name:"OSVDB", value:"50285");
  script_xref(name:"OSVDB", value:"57003");
  script_xref(name:"Secunia", value:"32715");

   script_name(english:"Mozilla Thunderbird < 2.0.0.18 Multiple Vulnerabilities");
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
      "The installed version of Thunderbird is earlier than 2.0.0.18.  Such\n",
      "versions are potentially affected by the following security issues :\n",
      "\n",
      "  - The canvas element can be used in conjunction with an\n",
      "    HTTP redirect to bypass same-origin restrictions and\n",
      "    gain access to the content in arbitrary images from\n",
      "    other domains. (MFSA 2008-48)\n",
      "\n",
      "  - By tampering with the window.__proto__.__proto__ object,\n",
      "    one can cause the browser to place a lock on a non-\n",
      "    native object, leading to a crash and possible code\n",
      "    execution. (MFSA 2008-50)\n",
      "\n",
      "  - There are several stability bugs in the browser engine\n",
      "    that may lead to crashes with evidence of memory\n",
      "    corruption. (MFSA 2008-52)\n",
      "\n",
      "  - Crashes and remote code execution in nsFrameManager are\n",
      "    possible by modifying certain properties of a file\n",
      "    input element before it has finished initializing.\n",
      "    (MFSA 2008-55)\n",
      "\n",
      "  - The same-origin check in\n",
      "    'nsXMLHttpRequest::NotifyEventListeners()' can be\n",
      "    bypassed. (MFSA 2008-56)\n",
      "\n",
      "  - There is an error in the method used to parse the\n",
      "    default namespace in an E4X document caused by quote\n",
      "    characters in the namespace not being properly escaped.\n",
      "    (MFSA 2008-58)\n",
      "\n",
      "  - Scripts in a malicous mail message can access the\n",
      "    .document URI and .textContext DOM properties.\n",
      "    (MFSA 2008-59)"
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-48.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-50.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-52.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-55.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-56.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-58.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-59.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Mozilla Thunderbird 2.0.0.18 or later."
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
  (ver[0] == 2 && ver[1] == 0 && ver[2] == 0 && ver[3] < 18)
) security_hole(get_kb_item("SMB/transport"));
