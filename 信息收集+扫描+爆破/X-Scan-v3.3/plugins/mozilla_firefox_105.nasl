#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(18689);
 script_version("$Revision: 1.13 $");

 script_cve_id("CVE-2005-1937", "CVE-2005-2260", "CVE-2005-2261", "CVE-2005-2262", "CVE-2005-2263",
               "CVE-2005-2264", "CVE-2005-2265", "CVE-2005-2266", "CVE-2005-2267", "CVE-2005-2268",
               "CVE-2005-2269", "CVE-2005-2270", "CVE-2005-2395");
 script_bugtraq_id(14242, 14325);
 script_xref(name:"OSVDB", value:"17913");
 script_xref(name:"OSVDB", value:"17942");
 script_xref(name:"OSVDB", value:"17964");
 script_xref(name:"OSVDB", value:"17965");
 script_xref(name:"OSVDB", value:"17966");
 script_xref(name:"OSVDB", value:"17967");
 script_xref(name:"OSVDB", value:"17968");
 script_xref(name:"OSVDB", value:"17969");
 script_xref(name:"OSVDB", value:"17970");
 script_xref(name:"OSVDB", value:"17971");
 script_xref(name:"OSVDB", value:"19002");

 script_name(english:"Firefox < 1.0.6 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote version of Firefox contains various security issues that
may allow an attacker execute arbitrary code on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2005/mfsa2005-45.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2005/mfsa2005-46.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2005/mfsa2005-47.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2005/mfsa2005-48.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2005/mfsa2005-49.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2005/mfsa2005-50.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2005/mfsa2005-51.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2005/mfsa2005-52.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2005/mfsa2005-53.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2005/mfsa2005-54.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2005/mfsa2005-55.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2005/mfsa2005-56.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 1.0.6 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Determines the version of Firefox");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("mozilla_org_installed.nasl");
 script_require_keys("Mozilla/Firefox/Version");
 exit(0);
}

#

include("misc_func.inc");

ver = read_version_in_kb("Mozilla/Firefox/Version");
if (isnull(ver)) exit(0);

if (
  ver[0] < 1 ||
  (ver[0] == 1 && ver[1] == 0 && ver[2] < 6)
) security_hole(get_kb_item("SMB/transport"));
