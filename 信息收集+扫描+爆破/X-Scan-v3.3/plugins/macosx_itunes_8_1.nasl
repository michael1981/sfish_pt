#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(35915);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2009-0143");
  script_bugtraq_id(34094);
  script_xref(name:"OSVDB", value:"52579");

  script_name(english:"iTunes < 8.1 Malicious Podcast Information Disclosure (Mac OS X)");
  script_summary(english:"Checks version of iTunes");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote Mac OS X host contains an application that is affected by\n",
      "a remote information disclosure vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The remote version of iTunes is affected by a remote information\n",
      "disclosure vulnerability.  By tricking a user on the affected host\n",
      "into authenticating to a malicious podcast, an attacker could gain the\n",
      "user's iTunes account information."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT3487"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2009/Mar/msg00001.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to iTunes 8.1 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N"
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
  (ver[0]==8 && ver[1] < 1)
)
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "iTunes ", version, " is currently installed on the remote host.\n"
    );
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
}

