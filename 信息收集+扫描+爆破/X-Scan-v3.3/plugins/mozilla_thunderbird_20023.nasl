#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40664);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2009-2408");
  script_bugtraq_id(35888);
  script_xref(name:"OSVDB", value:"56723");
  script_xref(name:"Secunia", value:"36088");

  script_name(english:"Mozilla Thunderbird < 2.0.0.23 Certificate Authority (CA) Common Name Null Byte Handling SSL MiTM Weakness");
  script_summary(english:"Checks version of Thunderbird");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote Windows host contains a mail client that is affected by a\n",
      "security bypass vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The installed version of Thunderbird is earlier than 2.0.0.23.  Such\n",
      "versions are potentially affected by the following security issue :\n",
      "\n",
      "  - The client can be fooled into trusting a malicious SSL\n",
      "    server certificate with a null character in the host name.\n",
      "    (MFSA 2009-42)"
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-42.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Thunderbird 2.0.0.23 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N"
  );
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/07/30"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/08/20"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/08/21"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


ver = read_version_in_kb("Mozilla/Thunderbird/Version");
if (isnull(ver)) exit(1, "The 'Mozilla/Thunderbird/Version' KB item is missing or invalid.");

if (
  ver[0] < 2 ||
  (ver[0] == 2 && ver[1] == 0 && ver[2] == 0 && ver[3] < 23)
) security_warning(get_kb_item("SMB/transport"));
else exit(0, "The system is not affected.");
