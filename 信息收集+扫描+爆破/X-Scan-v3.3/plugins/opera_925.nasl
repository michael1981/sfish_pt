#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(29742);
  script_version("$Revision: 1.7 $");

  script_cve_id(
    "CVE-2007-6520", 
    "CVE-2007-6521", 
    "CVE-2007-6522", 
    "CVE-2007-6523", 
    "CVE-2007-6524",
    "CVE-2009-2059",
    "CVE-2009-2063"
  );
  script_bugtraq_id(26721, 26937, 35380, 35412);
  script_xref(name:"OSVDB", value:"42691");
  script_xref(name:"OSVDB", value:"42692");
  script_xref(name:"OSVDB", value:"42693");
  script_xref(name:"OSVDB", value:"42694");
  script_xref(name:"OSVDB", value:"42695");
  script_xref(name:"OSVDB", value:"55131");

  script_name(english:"Opera < 9.25 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Opera");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by several
issues." );
 script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host reportedly is
affected by several issues, including one in which TLS certificates
could be used to execute arbitrary code." );
 script_set_attribute(attribute:"see_also", value:"http://research.microsoft.com/apps/pubs/default.aspx?id=79323" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/search/view/875/" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/search/view/876/" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/docs/changelogs/windows/925/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Opera version 9.25 or later." );
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

if (version_ui =~ "^([0-8]\.|9\.([01][0-9]|2[0-4])($|[^0-9]))")
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
