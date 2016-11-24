#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(27506);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2007-5540", "CVE-2007-5541");
  script_bugtraq_id(26100, 26102);
  script_xref(name:"OSVDB", value:"38126");
  script_xref(name:"OSVDB", value:"38127");

  script_name(english:"Opera < 9.24 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Opera");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by two
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host reportedly may allow
for arbitrary code execution if it has been configured to use an
external news reader or email client and a user views a
specially-crafted web page. 

In addition, it may also allow a script to bypass the same-origin
policy and overwrite functions on pages from other domains when
processing frames from different web sites, which can be leveraged to
conduct cross-site scripting attacks." );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/search/view/866/" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/search/view/867/" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/docs/changelogs/windows/924/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Opera version 9.24 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("opera_installed.nasl");
  script_require_keys("SMB/Opera/Version_UI");

  exit(0);
}


include("global_settings.inc");


version_ui = get_kb_item("SMB/Opera/Version_UI");
if (isnull(version_ui)) exit(0);

if (version_ui =~ "^([0-8]\.|9\.([01][0-9]|2[0-3])($|[^0-9]))")
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "Opera version ", version_ui, " is currently installed on the remote host.\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
