#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(41059);
  script_version("$Revision: 1.1 $");

  script_cve_id("CVE-2009-2817");
  script_bugtraq_id(36478);
  script_xref(name:"OSVDB", value:"58271");

  script_name(english:"iTunes < 9.0.1 PLS File Buffer Overflow (Mac OS X)");
  script_summary(english:"Checks version of iTunes");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote Mac OS X host contains an application affected by a buffer\n",
      "overflow vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The remote version of iTunes is older than 9.0.1. Such versions are\n",
      "affected by a buffer overflow involving the handling of PLS files.  If\n",
      "an attacker can trick a user on the affected host into opening a\n",
      "malicious PLS file, he can leverage this issue to crash the affected\n",
      "application or to execute arbitrary code on the affected system\n",
      "subject to the user's privileges."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT3884"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2009/sep/msg00006.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/advisories/17952"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to iTunes 9.0.1 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/09/22"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/09/23"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("macosx_itunes_detect.nasl");
  script_require_keys("MacOSX/iTunes/Version");

  exit(0);
}


include("global_settings.inc");


version = get_kb_item("MacOSX/iTunes/Version");
if (isnull(version)) exit(1, "The 'MacOSX/iTunes/Version' KB item is missing.");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 9 ||
  (ver[0] == 9 && ver[1] == 0 && ver[2] < 1)
)
{
  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "iTunes ", version, " is currently installed on the remote host.\n"
    );
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The host is not affected since iTunes "+version+" is installed.");
