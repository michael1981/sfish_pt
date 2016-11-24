#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(22371);
  script_version("$Revision: 1.12 $");

  script_cve_id(
    "CVE-2006-4253", 
    "CVE-2006-4340", 
    "CVE-2006-4565", 
    "CVE-2006-4566", 
    "CVE-2006-4568", 
    "CVE-2006-4570", 
    "CVE-2006-4571"
  );
  script_bugtraq_id(19488, 19534, 20042);
  script_xref(name:"OSVDB", value:"27974");
  script_xref(name:"OSVDB", value:"27975");
  script_xref(name:"OSVDB", value:"28843");
  script_xref(name:"OSVDB", value:"28844");
  script_xref(name:"OSVDB", value:"28846");
  script_xref(name:"OSVDB", value:"28848");
  script_xref(name:"OSVDB", value:"29012");
  script_xref(name:"OSVDB", value:"29013");

  script_name(english:"SeaMonkey < 1.0.5");
  script_summary(english:"Checks version of SeaMonkey");

 script_set_attribute(attribute:"synopsis", value:
"A web browser on the remote host is prone to multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The installed version of SeaMonkey contains various security issues,
some of which may lead to execution of arbitrary code on the affected
host subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-57.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-59.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-60.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-61.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-63.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-64.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to SeaMonkey 1.0.5 or later." );
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
  (ver[0] == 1 && ver[1] == 0 && ver[2] < 5)
) security_hole(get_kb_item("SMB/transport"));
