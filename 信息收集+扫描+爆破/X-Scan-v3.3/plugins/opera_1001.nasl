#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42291);
  script_version("$Revision: 1.4 $");

  script_cve_id(
    "CVE-2009-3265", 
    "CVE-2009-3266", 
    "CVE-2009-3831", 
    "CVE-2009-3832"
  );
  script_bugtraq_id(36418, 36850);
  script_xref(name:"OSVDB", value:"58258");
  script_xref(name:"OSVDB", value:"59357");
  script_xref(name:"OSVDB", value:"59358");
  script_xref(name:"OSVDB", value:"59359");
  script_xref(name:"Secunia", value:"37182");

  script_name(english:"Opera < 10.01 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Opera");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote host contains a web browser that is affected by multiple\n",
      "issues."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The version of Opera installed on the remote host is earlier than\n",
      "10.01.  Such versions are potential affected by multiple issues :\n",
      "\n",
      "  - Specially crafted domain names can cause a memory\n", 
      "    corruption in Opera, which may lead to a crash or\n",
      "    possibly remote code execution. (938)\n",
      "\n",
      "  - Opera may allow scripts to run on the feed subscription\n",
      "    page, thereby gaining access to the feeds object. (939)\n",
      "\n",
      "  - In some cases, a Web font intended to be used for page \n",
      "    content could be incorrectly used by Opera to render \n",
      "    parts of the user interface, including the address \n",
      "    field. (940)"
    )
  );

  script_set_attribute(
    attribute:"see_also",
    value:"http://www.opera.com/support/kb/view/938/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.opera.com/support/kb/view/939/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.opera.com/support/kb/view/940/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.opera.com/docs/changelogs/windows/1001/"
  );

  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Opera 10.01 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );

  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/10/28"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/10/28"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/10/28"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("opera_installed.nasl");
  script_require_keys("SMB/Opera/Version");

  exit(0);
}

include("global_settings.inc");

version_ui = get_kb_item("SMB/Opera/Version_UI");
version = get_kb_item("SMB/Opera/Version");
if (isnull(version)) exit(1, "The 'SMB/Opera/Version' KB item is missing.");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] < 10 ||
  (ver[0] == 10 && ver[1] < 1)
)
{
  if (report_verbosity > 0 && version_ui)
  {
    report = string(
      "\n",
      "Opera ", version_ui, " is currently installed on the remote host.\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(port:get_kb_item("SMB/transport"));
  exit(0);
}
exit(0, "The installed version of Opera is not affected.");
