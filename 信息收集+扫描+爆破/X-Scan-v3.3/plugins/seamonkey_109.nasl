#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25351);
  script_version("$Revision: 1.9 $");

  script_cve_id(
    "CVE-2007-1362",
    "CVE-2007-1558",
    "CVE-2007-2867",
    "CVE-2007-2868",
    "CVE-2007-2870",
    "CVE-2007-2871"
  );
  script_bugtraq_id(22879, 23257, 24242);
  script_xref(name:"OSVDB", value:"35134");
  script_xref(name:"OSVDB", value:"35136");
  script_xref(name:"OSVDB", value:"35137");
  script_xref(name:"OSVDB", value:"35138");
  script_xref(name:"OSVDB", value:"35139");

  script_name(english:"SeaMonkey < 1.0.9 / 1.1.2");
  script_summary(english:"Checks version of SeaMonkey");

 script_set_attribute(attribute:"synopsis", value:
"A web browser on the remote host is prone to multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The installed version of SeaMonkey contains various security issues,
one of which may lead to execution of arbitrary code on the affected
host subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-12.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-14.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-15.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-16.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-17.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to SeaMonkey 1.0.9 / 1.1.2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
 
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("SeaMonkey/Version");

  exit(0);
}


include("misc_func.inc");


ver = read_version_in_kb("SeaMonkey/Version");
if (isnull(ver)) exit(0);

if (
  ver[0] < 1 ||
  (
    ver[0] == 1 && 
    (
      (ver[1] == 0 && ver[2] < 9) ||
      (ver[1] == 1 && ver[2] < 2)
    )
  )
) security_hole(get_kb_item("SMB/transport"));
