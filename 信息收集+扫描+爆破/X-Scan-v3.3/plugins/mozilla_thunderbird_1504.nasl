#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(21628);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2006-2775", "CVE-2006-2776", "CVE-2006-2778", "CVE-2006-2779", 
                "CVE-2006-2780", "CVE-2006-2781", "CVE-2006-2783", "CVE-2006-2786", 
                "CVE-2006-2787");
  script_bugtraq_id(18228);
  script_xref(name:"OSVDB", value:"26298");
  script_xref(name:"OSVDB", value:"26300");
  script_xref(name:"OSVDB", value:"26301");
  script_xref(name:"OSVDB", value:"26302");
  script_xref(name:"OSVDB", value:"26303");
  script_xref(name:"OSVDB", value:"26304");
  script_xref(name:"OSVDB", value:"26305");
  script_xref(name:"OSVDB", value:"26306");
  script_xref(name:"OSVDB", value:"26307");
  script_xref(name:"OSVDB", value:"26308");
  script_xref(name:"OSVDB", value:"26310");
  script_xref(name:"OSVDB", value:"26311");
  script_xref(name:"OSVDB", value:"26312");
  script_xref(name:"OSVDB", value:"26314");

  script_name(english:"Mozilla Thunderbird < 1.5.0.4 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Mozilla Thunderbird");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a mail client that is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote version of Mozilla Thunderbird suffers from various security issues,
some of which may lead to execution of arbitrary code on the affected
host subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-31.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-32.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-33.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-35.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-37.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-38.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-40.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-42.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird 1.5.0.4 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");
  exit(0);
}

#

include("misc_func.inc");

ver = read_version_in_kb("Mozilla/Thunderbird/Version");
if (isnull(ver)) exit(0);

if (
  ver[0] < 1 ||
  (
    ver[0] == 1 &&
    (
      ver[1] < 5 ||
      (ver[1] == 5 && ver[2] == 0 && ver[3] < 4)
    )
  )
) security_hole(get_kb_item("SMB/transport"));
