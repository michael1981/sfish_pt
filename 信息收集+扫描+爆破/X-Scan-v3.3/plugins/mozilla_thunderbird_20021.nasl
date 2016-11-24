#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(35977);
  script_version("$Revision: 1.3 $");

  script_cve_id(
    "CVE-2009-0040",
    "CVE-2009-0352", 
    "CVE-2009-0353",
    "CVE-2009-0652",
    "CVE-2009-0771",
    "CVE-2009-0772",
    "CVE-2009-0773",
    "CVE-2009-0774",
    "CVE-2009-0776"
  );
  script_bugtraq_id(33598, 33827, 33837, 33990);
  if (NASL_LEVEL >= 3000)
  {
    script_xref(name:"OSVDB", value:"51929");
    script_xref(name:"OSVDB", value:"51931");
    script_xref(name:"OSVDB", value:"51932");
    script_xref(name:"OSVDB", value:"51933");
    script_xref(name:"OSVDB", value:"51934");
    script_xref(name:"OSVDB", value:"51935");
    script_xref(name:"OSVDB", value:"51936");
    script_xref(name:"OSVDB", value:"51937");
    script_xref(name:"OSVDB", value:"51938");
    script_xref(name:"OSVDB", value:"51939");
    script_xref(name:"OSVDB", value:"51940");
    script_xref(name:"OSVDB", value:"52659");
    script_xref(name:"OSVDB", value:"53315");
    script_xref(name:"OSVDB", value:"53316");
    script_xref(name:"OSVDB", value:"53317");
  }

  script_name(english:"Mozilla Thunderbird < 2.0.0.21 Multiple Vulnerabilities");
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
      "The installed version of Thunderbird is earlier than 2.0.0.21.  Such\n",
      "versions are potentially affected by the following security issues :\n",
      "\n",
      "  - There are several stability bugs in the browser engine\n",
      "    that may lead to crashes with evidence of memory\n",
      "    corruption. (MFSA 2009-01)\n",
      "\n",
      "  - By exploiting stability bugs in the browser engine, it \n",
      "    might be possible for an attacker to execute arbitrary \n",
      "    code on the remote system under certain conditions. \n",
      "    (MFSA 2009-07)\n",
      "\n",
      "  - It may be possible for a website to read arbitrary XML\n",
      "    data from another domain by using nsIRDFService and a \n",
      "    cross-domain redirect. (MFSA 2009-09)\n",
      "\n",
      "  - Vulnerabilities in the PNG libraries used by Mozilla\n",
      "    could be exploited to execute arbitrary code on the \n",
      "    remote system. (MFSA 2009-10)\n",
      "\n",
      "  - A URI-spoofing vulnerability exists because the \n",
      "    application fails to adequately handle specific \n",
      "    characters in IDN subdomains. (MFSA 2009-15)"
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-01.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-07.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-09.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-10.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-15.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.mozilla.com/en-US/thunderbird/2.0.0.21/releasenotes/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Mozilla Thunderbird 2.0.0.21 or later."
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
  (ver[0] == 2 && ver[1] == 0 && ver[2] == 0 && ver[3] < 21)
) security_hole(get_kb_item("SMB/transport"));
