#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
  script_id(34680);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2008-4794", "CVE-2008-4795");
  script_bugtraq_id(31991);
  script_xref(name:"OSVDB", value:"49472");
  script_xref(name:"OSVDB", value:"49473");

  script_name(english:"Opera < 9.62 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Opera");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by several
issues." );
 script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host is earlier than 9.62
and thus reportedly affected by several issues :

  - Opera fails to sanitize certain parameters passed to the
    'History Search' (906).

  - The browser's same-origin policy may be violated because
    scripts running in the 'Links Panel' always run in the
    outermost frame of the page (907).

Successful exploitation would result in the attacker being able to
execute arbitrary script code in the unsuspecting user's browser and
may also lead to cookie-based credential theft, browser setting
modifications, and other attacks. 

These attacks require that the attacker be able to trick a user into
browsing to a malicious URI with the affected application." );
 script_set_attribute(attribute:"see_also", value:"http://aviv.raffon.net/2008/10/30/AdifferentOpera.aspx" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/search/view/906/" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/search/view/907/" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/docs/changelogs/windows/962/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Opera 9.62 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

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
      ver[1]  < 62
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
