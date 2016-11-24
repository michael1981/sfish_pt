#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(35761);
  script_version("$Revision: 1.4 $");

  script_cve_id(
    "CVE-2009-0914",
    "CVE-2009-0915",
    "CVE-2009-0916",
    "CVE-2009-2540"
  );
  script_bugtraq_id(33961, 35446);

  script_name(english:"Opera < 9.64 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Opera");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
issues." );
 script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host is earlier than 9.64
and thus reportedly affected by multiple issues :

  - A memory-corruption vulnerability when processing specially
    crafted JPEG files could allow an attacker to execute arbitrary
    code with the privileges of the affected application. (926)
  
  - It may be possible for certain plugins to execute arbitrary code
    in the context of a different domain. An attacker could exploit
    this to steal authentication credentials as well as carry out
    other attacks.

  - Creating a Select object with a very large length can
    result in memory exhaustion, which could cause the system
    to become unstable. (CVE-2009-2540)" );
    
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/504969/100/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/docs/changelogs/windows/964" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/926" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Opera 9.64 or later." );
 script_set_attribute(attribute:"cvss_vector", value:
"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

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
if (isnull(version)) exit(0);

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 9 ||
  (
    ver[0] == 9 &&
    (
      ver[1] < 64
    )
  )
)
{
  if (report_verbosity && version_ui)
  {
    report = string(
      "\n",
      "Opera ", version_ui, " is currently installed on the remote host.\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
