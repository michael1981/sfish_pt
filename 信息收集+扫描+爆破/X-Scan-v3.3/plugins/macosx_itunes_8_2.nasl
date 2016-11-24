#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(38987);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2009-0950");
  script_bugtraq_id(35157);
  script_xref(name:"OSVDB", value:"54833");

  script_name(english:"iTunes < 8.2 itms: URL Stack Overflow (Mac OS X)");
  script_summary(english:"Checks version of iTunes");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote Mac OS X host contains an application that is affected by a\n",
      "buffer overflow vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The remote version of iTunes is older than 8.2. Such versions are\n",
      "affected by a stack-based buffer overflow that can be triggered\n",
      "when parsing 'itms:' URLs.  If an attacker can trick a user on the\n",
      "affected host into clicking on a malicious link, he can leverage\n",
      "this issue to crash the affected application or to execute arbitrary\n",
      "code on the affected system subject to the user's privileges."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT3592"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2009/jun/msg00001.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to iTunes 8.2 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
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
if (isnull(version)) exit(0);

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if 
(
  ver[0] < 8 ||
  (ver[0] == 8 && ver[1] < 2)
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

