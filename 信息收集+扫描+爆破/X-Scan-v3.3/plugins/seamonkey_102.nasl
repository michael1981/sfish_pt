#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(21629);
  script_version("$Revision: 1.14 $");

  script_cve_id(
    "CVE-2006-1942",
    "CVE-2006-2775",
    "CVE-2006-2776",
    "CVE-2006-2777",
    "CVE-2006-2778",
    "CVE-2006-2779", 
    "CVE-2006-2780", 
    "CVE-2006-2781",
    "CVE-2006-2782", 
    "CVE-2006-2783",
    "CVE-2006-2785",
    "CVE-2006-2786", 
    "CVE-2006-2787"
  );
  script_bugtraq_id(18228);
  if (NASL_LEVEL >= 3000)
  {
    script_xref(name:"OSVDB", value:"24713");
    script_xref(name:"OSVDB", value:"26298");
    script_xref(name:"OSVDB", value:"26299");
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
    script_xref(name:"OSVDB", value:"26313");
    script_xref(name:"OSVDB", value:"26314");
    script_xref(name:"OSVDB", value:"26315");
  }

  script_name(english:"SeaMonkey < 1.0.2");
  script_summary(english:"Checks version of SeaMonkey");

 script_set_attribute(attribute:"synopsis", value:
"A web browser on the remote host is prone to multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The installed version of SeaMonkey contains various security issues,
some of which may lead to execution of arbitrary code on the affected
host subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-31.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-32.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-33.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-34.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-35.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-37.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-38.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-39.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-40.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-41.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-42.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-43.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to SeaMonkey 1.0.2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
 
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
 
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("SeaMonkey/Version");

  exit(0);
}


include("misc_func.inc");


ver = read_version_in_kb("SeaMonkey/Version");
if (isnull(ver)) exit(0);

if (
  ver[0] < 1 ||
  (ver[0] == 1 && ver[1] == 0 && ver[2] < 2)
) security_hole(get_kb_item("SMB/transport"));
