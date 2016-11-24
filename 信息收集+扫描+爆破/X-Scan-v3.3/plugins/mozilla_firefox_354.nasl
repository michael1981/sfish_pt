#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");


if (description)
{
  script_id(42306);
  script_version("$Revision: 1.2 $");

  script_cve_id(
    "CVE-2009-1563",
    "CVE-2009-3274",
    "CVE-2009-3370",
    "CVE-2009-3371",
    "CVE-2009-3372",
    "CVE-2009-3373",
    "CVE-2009-3374",
    "CVE-2009-3375",
    "CVE-2009-3376",
    "CVE-2009-3377",
    "CVE-2009-3378",
    "CVE-2009-3379",
    "CVE-2009-3380",
    "CVE-2009-3381",
    "CVE-2009-3382",
    "CVE-2009-3383"
  );
  script_bugtraq_id(36851, 36852, 36853, 36854, 36855, 36856, 36857, 36858, 36866, 36867, 36869, 36870, 36871, 36872, 36873, 36875);
  script_xref(name:"OSVDB", value:"59381");
  script_xref(name:"OSVDB", value:"59382");
  script_xref(name:"OSVDB", value:"59383");
  script_xref(name:"OSVDB", value:"59384");
  script_xref(name:"OSVDB", value:"59385");
  script_xref(name:"OSVDB", value:"59386");
  script_xref(name:"OSVDB", value:"59387");
  script_xref(name:"OSVDB", value:"59388");
  script_xref(name:"OSVDB", value:"59389");
  script_xref(name:"OSVDB", value:"59390");
  script_xref(name:"OSVDB", value:"59391");
  script_xref(name:"OSVDB", value:"59392");
  script_xref(name:"OSVDB", value:"59393");
  script_xref(name:"OSVDB", value:"59394");
  script_xref(name:"OSVDB", value:"59395");
  script_xref(name:"Secunia", value:"36711");

  script_name(english:"Firefox < 3.5.4 Multiple Vulnerabilities");
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
      "The installed version of Firefox is earlier than 3.5.4.  Such\n",
      "versions are potentially affected by the following security issues :\n",
      "\n",
      "  - It may be possible for a malicious web page to\n",
      "    steal form history. (MFSA 2009-52)\n",
      "\n",
      "  - By predicting the filename of an already \n",
      "    downloaded file in the downloads directory, a\n",
      "    local attacker may be able to trick the browser\n",
      "    into opening an incorrect file. (MFSA 2009-53)\n",
      "\n",
      "  - Recursive creation of JavaScript web-workers \n",
      "    could crash the browser or allow execution of \n",
      "    arbitrary code on the remote system.\n",
      "    (MFSA 2009-54)\n",
      "\n",
      "  - Provided the browser is configured to use Proxy\n",
      "    Auto-configuration it may be possible for an \n",
      "    attacker to crash the browser or execute\n", 
      "    arbitrary code. (MFSA 2009-55)\n",
      "\n",
      "  - Mozilla's GIF image parser is affected by a \n",
      "    heap-based buffer overflow. (MFSA 2009-56)\n",
      "\n",
      "  - A vulnerability in XPCOM utility\n", 
      "    'XPCVariant::VariantDataToJS' could allow \n",
      "    executing arbitrary JavaScript code with chrome\n",
      "    privileges. (MFSA 2009-57)\n",
      "\n",
      "  - A vulnerability in Mozilla's string to floating\n",
      "    point number conversion routine could allow \n",
      "    arbitrary code execution on the remote system. \n",
      "    (MFSA 2009-59)\n",
      "\n",
      "  - It may be possible to read text from a web page \n",
      "    using JavaScript function 'document.getSelection()\n",
      "    from a different domain. (MFSA 2009-61)\n",
      "\n",
      "  - If a file contains right-to-left override \n",
      "    character (RTL) in the filename it may be possible\n",
      "    for an attacker to obfuscate the filename and \n",
      "    extension of the file being downloaded. \n",
      "    (MFSA 2009-62)\n",
      "\n",
      "  - Multiple memory safety bugs in media libraries\n",
      "    could potentially allow arbitrary code execution.\n",
      "    (MFSA 2009-63)\n",
      "\n",
      "  - Multiple memory corruption vulnerabilities could\n",
      "    potentially allow arbitrary code execution.\n",
      "    (MFSA 2009-64)\n"
      )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-52.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-53.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-54.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-55.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-56.html"
  );
  script_set_attribute( 
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-57.html"
  );  
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-59.html"
  );  
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-61.html"
  );  
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-62.html"
  );  
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-63.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-64.html"
  );  

  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Firefox 3.5.4 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/10/27"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/10/27"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/10/29"
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
if (ver[0] == 3 && ver[1] == 5 && ver[2] < 4)
  security_hole(get_kb_item("SMB/transport"));
else
  exit(0, "No vulnerable versions of Firefox were found.");

