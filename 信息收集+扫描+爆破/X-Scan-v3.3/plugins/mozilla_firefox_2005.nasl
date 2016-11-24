#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25735);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2007-3089", "CVE-2007-3285", "CVE-2007-3656", "CVE-2007-3734",
                "CVE-2007-3735", "CVE-2007-3736", "CVE-2007-3737", "CVE-2007-3738");
  script_bugtraq_id(24286, 24447, 24831, 24946);
  script_xref(name:"OSVDB", value:"38000");
  script_xref(name:"OSVDB", value:"38001");
  script_xref(name:"OSVDB", value:"38002");
  script_xref(name:"OSVDB", value:"38010");
  script_xref(name:"OSVDB", value:"38015");
  script_xref(name:"OSVDB", value:"38016");
  script_xref(name:"OSVDB", value:"38024");
  script_xref(name:"OSVDB", value:"38028");
  script_xref(name:"OSVDB", value:"38032");

  script_name(english:"Firefox < 2.0.0.5 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The installed version of Firefox is affected by various security
issues, one of which may lead to execution of arbitrary code on the
affected host subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-18.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-19.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-20.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-21.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-22.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-23.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-24.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-25.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 2.0.0.5 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");
  exit(0);
}

#

include("misc_func.inc");

ver = read_version_in_kb("Mozilla/Firefox/Version");
if (isnull(ver)) exit(0);

if (
  ver[0] < 2 ||
  (ver[0] == 2 && ver[1] == 0 && ver[2] == 0 && ver[3] < 5)
) security_hole(get_kb_item("SMB/transport"));
