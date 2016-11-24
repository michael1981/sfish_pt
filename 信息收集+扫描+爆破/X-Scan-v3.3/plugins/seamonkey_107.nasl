#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(23928);
  script_version("$Revision: 1.6 $");

  script_cve_id(
    "CVE-2006-6497",
    "CVE-2006-6498",
    "CVE-2006-6499",
    "CVE-2006-6500",
    "CVE-2006-6501",
    "CVE-2006-6502",
    "CVE-2006-6503",
    "CVE-2006-6504",
    "CVE-2006-6505"
  );
  script_bugtraq_id(21668);
  script_xref(name:"OSVDB", value:"31341");
  script_xref(name:"OSVDB", value:"31342");
  script_xref(name:"OSVDB", value:"31343");
  script_xref(name:"OSVDB", value:"31344");
  script_xref(name:"OSVDB", value:"31345");
  script_xref(name:"OSVDB", value:"31346");
  script_xref(name:"OSVDB", value:"31347");
  script_xref(name:"OSVDB", value:"31348");
  script_xref(name:"OSVDB", value:"31349");
  script_xref(name:"OSVDB", value:"31350");

  script_name(english:"SeaMonkey < 1.0.7");
  script_summary(english:"Checks version of SeaMonkey");

 script_set_attribute(attribute:"synopsis", value:
"A web browser on the remote host is prone to multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The installed version of SeaMonkey contains various security issues,
some of which may lead to execution of arbitrary code on the affected
host subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-68.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-69.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-70.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-71.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-72.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-73.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-74.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to SeaMonkey 1.0.7 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
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
  (ver[0] == 1 && ver[1] == 0 && ver[2] < 7)
) security_hole(get_kb_item("SMB/transport"));
