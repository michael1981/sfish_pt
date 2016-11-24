#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(18813);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2005-1937", "CVE-2005-2260", "CVE-2005-2261", "CVE-2005-2263",
                "CVE-2005-2265", "CVE-2005-2266", "CVE-2005-2268", "CVE-2005-2269",
                "CVE-2005-2270");
  script_bugtraq_id(14242);
  script_xref(name:"OSVDB", value:"17397");
  script_xref(name:"OSVDB", value:"17913");
  script_xref(name:"OSVDB", value:"17942");
  script_xref(name:"OSVDB", value:"17964");
  script_xref(name:"OSVDB", value:"17966");
  script_xref(name:"OSVDB", value:"17968");
  script_xref(name:"OSVDB", value:"17969");
  script_xref(name:"OSVDB", value:"17970");
  script_xref(name:"OSVDB", value:"7296");

  script_name(english:"Mozilla Browser < 1.7.9 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote host contains multiple
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote version of this software contains various security issues,
one of which may allow an attacker to execute arbitrary code on the
remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2005/mfsa2005-45.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2005/mfsa2005-46.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2005/mfsa2005-48.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2005/mfsa2005-50.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2005/mfsa2005-51.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2005/mfsa2005-52.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2005/mfsa2005-54.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2005/mfsa2005-55.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2005/mfsa2005-56.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla 1.7.9 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

  script_summary(english:"Checks for Mozilla < 1.7.9");
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Version");
  exit(0);
}

#

include("misc_func.inc");


ver = read_version_in_kb("Mozilla/Version");
if (isnull(ver)) exit(0);

if (
  ver[0] < 1 ||
  (
    ver[0] == 1 &&
    (
      ver[1] < 7 ||
      (ver[1] == 7 && ver[2] < 9)
    )
  )
) security_hole(get_kb_item("SMB/transport"));
