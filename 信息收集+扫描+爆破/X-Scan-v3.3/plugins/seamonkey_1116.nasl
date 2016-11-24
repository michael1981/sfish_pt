#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(36130);
  script_version("$Revision: 1.3 $");

  script_cve_id(
    "CVE-2009-1169",
    "CVE-2009-1302",
    "CVE-2009-1303",
    "CVE-2009-1304",
    "CVE-2009-1305"
  );
  script_bugtraq_id(34656, 34235);
  script_xref(name:"OSVDB", value:"53079");

  script_name(english:"SeaMonkey < 1.1.16");
  script_summary(english:"Checks version of SeaMonkey");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "A web browser on the remote host is affected by multiple\n",
      "vulnerabilities."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The installed version of SeaMonkey is earlier than 1.1.16.  Such\n",
      "versions are potentially affected by the following security issues :\n",
      "\n",
      "  - An XSL transformation vulnerability can be leveraged \n",
      "    with a specially crafted stylesheet to crash the browser\n",
      "    or to execute arbitrary code. (MFSA 2009-12)\n",
      "\n",
      "  - Multiple remote memory corruption vulnerabilities exist\n",
      "    which can be exploited to execute arbitrary code in the\n",
      "    context of the user running the affected application.\n",
      "    (MFSA 2009-14)"
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-12.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-14.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to SeaMonkey 1.1.16 or later."
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
      ver[1] == 0 ||
      (ver[1] == 1 && ver[2] < 16)
    )
  )
) security_hole(get_kb_item("SMB/transport"));
