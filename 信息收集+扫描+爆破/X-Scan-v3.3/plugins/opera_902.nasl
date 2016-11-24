#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(22875);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2006-4819");
  script_bugtraq_id(20591);
  script_xref(name:"OSVDB", value:"29785");

  script_name(english:"Opera < 9.02 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Opera");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is susceptible to a heap
buffer overflow attack." );
 script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host reportedly contains
a heap buffer overflow vulnerability that can be triggered by a long
link.  Successful exploitation of this issue may result in a crash of
the application or even allow for execution of arbitrary code subject
to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=424" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2006-10/0347.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/search/supsearch.dml?index=848" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Opera version 9.02 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("opera_installed.nasl");
  script_require_keys("SMB/Opera/Version_UI");

  exit(0);
}


include("global_settings.inc");


version_ui = get_kb_item("SMB/Opera/Version_UI");
if (isnull(version_ui)) exit(0);

if (version_ui =~ "^9\.0[01]($|[^0-9])")
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "Opera version ", version_ui, " is currently installed on the remote host.\n"
    );
    security_warning(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_warning(get_kb_item("SMB/transport"));
}
