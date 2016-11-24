#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(34695);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2008-2549", "CVE-2008-2992", "CVE-2008-4812", "CVE-2008-4813",
                "CVE-2008-4814", "CVE-2008-4816", "CVE-2008-4817", "CVE-2008-5364");
  script_bugtraq_id(29420, 30035, 32100, 32103, 32105);
  script_xref(name:"OSVDB", value:"46211");
  script_xref(name:"OSVDB", value:"49520");
  script_xref(name:"OSVDB", value:"49541");  
  script_xref(name:"OSVDB", value:"50243");
  script_xref(name:"OSVDB", value:"50245");
  script_xref(name:"OSVDB", value:"50246");
  script_xref(name:"OSVDB", value:"50247");
  script_xref(name:"OSVDB", value:"50639");
  script_xref(name:"Secunia", value:"29773");

  script_name(english:"Adobe Reader < 8.1.3 / 9.0 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Adobe Reader");

 script_set_attribute(attribute:"synopsis", value:
"The PDF file viewer on the remote Windows host is affected by multiple
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote host is earlier
than 8.1.3.  Such versions are reportedly affected by multiple
vulnerabilities :

  - There is a publicly-published denial of service issue
    (CVE-2008-2549).

  - A stack-based buffer overflow when parsing format 
    strings containing a floating point specifier in the 
    'util.printf()' JavaScript function may allow an
    attacker to execute arbitrary code (CVE-2008-2992).

  - Multiple input validation errors could lead to code
    execution (CVE-2008-4812).

  - Multiple input validation issues could lead to remote
    code execution. (CVE-2008-4813)

  - A heap corruption vulnerability in an AcroJS function
    available to scripting code inside of a PDF document
    could lead to remote code execution. (CVE-2008-4817)

  - An input validation issue in the Download Manager used 
    by Adobe Reader could lead to remote code execution 
    during the download process (CVE-2008-5364).

  - An issue in the Download Manager used by Adobe Reader 
    could lead to a user's Internet Security options being 
    changed during the download process (CVE-2008-4816).

  - An input validation issue in a JavaScript method could 
    lead to remote code execution (CVE-2008-4814)." );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2008-14/" );
 script_set_attribute(attribute:"see_also", value:"http://www.coresecurity.com/content/adobe-reader-buffer-overflow" );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=754" );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=755" );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=756" );
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-072" );
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-073" );
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-074" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/498027/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/498032/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2008-11/0073.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2008-11/0074.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2008-11/0075.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2008-11/0076.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb08-19.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader 9.0 / 8.1.3 or later." );
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
  (
    ver =~ "^[0-6]\." ||
    ver =~ "^7\.(0\.|1\.0\.)" ||
    ver =~ "^8\.(0\.|1\.[0-2][^0-9.]?)"
  )
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
