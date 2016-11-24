#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40874);
  script_version("$Revision: 1.1 $");

  script_cve_id("CVE-2009-2404", "CVE-2009-2408");
  script_bugtraq_id(35888, 35891);
  script_xref(name:"OSVDB", value:"56723");
  script_xref(name:"OSVDB", value:"56724");
  script_xref(name:"Secunia", value:"36125");

  script_name(english:"SeaMonkey < 1.1.18 Multiple Vulnerabilities");
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
      "The installed version of SeaMonkey is earlier than 1.1.18.  Such\n",
      "versions are potentially affected by the following security issues :\n",
      "\n",
      "  - The browser can be fooled into trusting a malicious SSL\n",
      "    server certificate with a null character in the host name.\n",
      "    (MFSA 2009-42)\n",
      "\n",
      "  - A heap overflow in the code that handles regular\n",
      "    expressions in certificate names can lead to\n",
      "    arbitrary code execution. (MFSA 2009-43)"
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-42.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-43.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to SeaMonkey 1.1.18 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/07/30"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/09/03"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/09/04"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("SeaMonkey/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


ver = read_version_in_kb("SeaMonkey/Version");
if (isnull(ver)) exit(1, "The 'SeaMonkey/Version' KB item is missing.");

if (
  ver[0] < 1 ||
  (ver[0] == 1 && ver[1] < 1) ||
  (ver[0] == 1 && ver[1] == 1 && ver[2] < 18)
) security_hole(get_kb_item("SMB/transport"));
else exit(0, "No vulnerable versions of SeaMonkey were found.");
