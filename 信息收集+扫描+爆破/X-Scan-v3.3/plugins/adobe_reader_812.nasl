#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(30200);
  script_version("$Revision: 1.14 $");

  script_cve_id(
    #"CVE-2007-4768",  heap overflow in PCRE library
    "CVE-2007-5659", "CVE-2007-5663", "CVE-2007-5666", "CVE-2008-0655",
    "CVE-2008-0667", "CVE-2008-0726", "CVE-2008-2042");
  script_bugtraq_id(27641);
  script_xref(name:"OSVDB", value:"41492");
  script_xref(name:"OSVDB", value:"41493");
  script_xref(name:"OSVDB", value:"41494");
  script_xref(name:"OSVDB", value:"41495");
  script_xref(name:"OSVDB", value:"42683");
  script_xref(name:"OSVDB", value:"44998");
  script_xref(name:"OSVDB", value:"46549");

  script_name(english:"Adobe Reader < 7.1.0 / 8.1.2 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Adobe Reader");

 script_set_attribute(attribute:"synopsis", value:
"The PDF file viewer on the remote Windows host is affected by multiple
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote host is earlier
than 8.1.2 or 7.1.0.  Such versions are reportedly affected by
multiple vulnerabilities :

  - A design error vulnerability may allow an attacker to 
    gain control of a user's printer.

  - Multiple stack-based buffer overflows may allow an
    attacker to execute arbitrary code subject to the 
    user's privileges.

  - Insecure loading of 'Security Provider' libraries may
    allow for arbitrary code execution.

  - An insecure method exposed by the JavaScript library
    in the 'EScript.api' plug-in allows direct control
    over low-level features of the object, which allows 
    for execution of arbitrary code as the current user.

  - Two vulnerabilities in the unpublicized function
    'app.checkForUpdate()' exploited through a callback 
    function could lead to arbitrary code execution in
    Adobe Reader 7." );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=655" );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=656" );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=657" );
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-004.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2008-02/0080.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2008-02/0104.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2008-02/0105.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2008-02/0106.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2008-02/0147.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2008-05/0141.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2008-05/0142.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/go/kb403079" );
 script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/advisories/apsa08-01.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb08-13.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader 8.1.2 / 7.1.0 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
  script_dependencies("adobe_reader_installed.nasl");
  script_require_keys("SMB/Acroread/Version");
  exit(0);
}

#

include("global_settings.inc");

ver = get_kb_item("SMB/Acroread/Version");
if (
  ver && 
  ver =~ "^([0-6]\.|7\.0|8\.(0\.|1\.[01][^0-9.]?))"
)
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "The remote version of Adobe Reader is ", ver, ".\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
