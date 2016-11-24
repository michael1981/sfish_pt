#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(22097);
  script_version("$Revision: 1.13 $");

  script_cve_id(
    "CVE-2006-3113",
    "CVE-2006-3677",
    "CVE-2006-3801",
    "CVE-2006-3802",
    "CVE-2006-3803",
    "CVE-2006-3804",
    "CVE-2006-3805",
    "CVE-2006-3806",
    "CVE-2006-3807",
    "CVE-2006-3808",
    "CVE-2006-3809",
    "CVE-2006-3810",
    "CVE-2006-3811",
    "CVE-2006-3812"
  );
  script_bugtraq_id(19181, 19192, 19197);
  if (NASL_LEVEL >= 3000)
  {
  script_xref(name:"OSVDB", value:"27559");
    script_xref(name:"OSVDB", value:"27560");
    script_xref(name:"OSVDB", value:"27561");
    script_xref(name:"OSVDB", value:"27562");
    script_xref(name:"OSVDB", value:"27563");
    script_xref(name:"OSVDB", value:"27564");
    script_xref(name:"OSVDB", value:"27565");
    script_xref(name:"OSVDB", value:"27566");
    script_xref(name:"OSVDB", value:"27567");
    script_xref(name:"OSVDB", value:"27568");
    script_xref(name:"OSVDB", value:"27569");
    script_xref(name:"OSVDB", value:"27570");
    script_xref(name:"OSVDB", value:"27571");
    script_xref(name:"OSVDB", value:"27572");
    script_xref(name:"OSVDB", value:"27573");
    script_xref(name:"OSVDB", value:"27574");
    script_xref(name:"OSVDB", value:"27575");
    script_xref(name:"OSVDB", value:"27576");
    script_xref(name:"OSVDB", value:"27577");
  }

  script_name(english:"SeaMonkey < 1.0.3");
  script_summary(english:"Checks version of SeaMonkey");

 script_set_attribute(attribute:"synopsis", value:
"A web browser on the remote host is prone to multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The installed version of SeaMonkey contains various security issues,
some of which may lead to execution of arbitrary code on the affected
host subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-44.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-45.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-46.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-47.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-48.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-49.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-50.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-51.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-52.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-53.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-54.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-55.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-56.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to SeaMonkey 1.0.3 or later." );
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
  (ver[0] == 1 && ver[1] == 0 && ver[2] < 3)
) security_hole(get_kb_item("SMB/transport"));
