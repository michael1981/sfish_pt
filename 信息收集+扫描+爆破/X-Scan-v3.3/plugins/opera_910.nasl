#
# (C) Tenable Network Security
#



include("compat.inc");

if (description)
{
  script_id(23977);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2007-0126", "CVE-2007-0127");
  script_bugtraq_id(21882);
  script_xref(name:"OSVDB", value:"31574");
  script_xref(name:"OSVDB", value:"31575");

  script_name(english:"Opera < 9.10 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Opera");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is susceptible to
multiple issues." );
 script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host reportedly contains
a heap overflow vulnerability that can be triggered when processing
the DHT marker in a specially-crafted JPEG image to crash the browser
or possibly allow execution of arbitrary code on the affected host. 

In addition, another flaw in Opera's createSVGTransformFromMatrix
object typecasting may lead to a browser crash or arbitrary code
execution if support for JavaScript is enabled." );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=458" );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=457" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/456053" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/456066" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/search/supsearch.dml?index=851" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/search/supsearch.dml?index=852" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Opera version 9.10 or later." );
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

if (version_ui =~ "^9\.0[0-9]($|[^0-9])")
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
