#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40804);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2009-1492");
  script_bugtraq_id(34736);
  script_xref(name:"OSVDB", value:"54130");
  script_xref(name:"Secunia", value:"34924");

  script_name(english:"Adobe Acrobat < 9.1.1 / 8.1.5 / 7.1.2 getAnnots() JavaScript Method PDF Handling Memory Corruption");
  script_summary(english:"Checks version of Adobe Acrobat");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The version of Adobe Acrobat on the remote Windows host is affected by\n",
      "a memory corruption vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The version of Adobe Acrobat installed on the remote host is earlier\n",
      "than 9.1.1 / 8.1.5 / 7.1.2.  Such versions reportedly fail to validate\n",
      "input from a specially crafted PDF file before passing it to the\n",
      "JavaScript method 'getAnnots()' leading to memory corruption and\n",
      "possibly arbitrary code execution."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.adobe.com/support/security/advisories/apsa09-02.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kb.cert.org/vuls/id/970180"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.adobe.com/support/security/bulletins/apsb09-06.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Adobe Acrobat 9.1.1 / 8.1.5 / 7.1.2 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );

  script_set_attribute( attribute:'vuln_publication_date', value:'2009/05/01' );
  script_set_attribute( attribute:'patch_publication_date', value:'2009/05/12' );
  script_set_attribute( attribute:'plugin_publication_date', value:'2009/08/28' );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("adobe_acrobat_installed.nasl");
  script_require_keys("SMB/Acrobat/Version");

  exit(0);
}


include("global_settings.inc");

version = get_kb_item("SMB/Acrobat/Version");
if (isnull(version)) exit(1, "The 'SMB/Acrobat/Version' KB item is missing.");

if (
  version =~ "^[0-6]\." ||
  version =~ "^7\.(0\.|1\.[01]($|[^0-9]))" ||
  version =~ "^8\.(0\.|1\.[0-4]($|[^0-9]))" ||
  version =~ "^9\.(0\.|1\.0($|[^0-9]))"
)
{
  version_ui = get_kb_item("SMB/Acrobat/Version_UI");
  if (report_verbosity > 0 && version_ui)
  {
    path = get_kb_item("SMB/Acrobat/Path");
    if (isnull(path)) path = "n/a";

    report = string(
      "\n",
      "  Path              : ", path, "\n",
      "  Installed version : ", version_ui, "\n",
      "  Fix               : 9.1.1 / 8.1.5 / 7.1.2\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
else exit(0, "Acrobat "+version+" is not affected.");
