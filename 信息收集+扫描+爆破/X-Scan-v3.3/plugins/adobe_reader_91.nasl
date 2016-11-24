#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(35821);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2009-0193", "CVE-2009-0658", "CVE-2009-0927", "CVE-2009-0928",
                "CVE-2009-1061", "CVE-2009-1062");
  script_bugtraq_id(33751, 34169, 34229);
  script_xref(name:"milw0rm", value:"8099");
  script_xref(name:"OSVDB", value:"52073");
  script_xref(name:"OSVDB", value:"53644");
  script_xref(name:"OSVDB", value:"53645");
  script_xref(name:"OSVDB", value:"53646");
  script_xref(name:"OSVDB", value:"53647");
  script_xref(name:"OSVDB", value:"53648");
  script_xref(name:"Secunia", value:"33901");

  script_name(english:"Adobe Reader < 9.1 / 8.1.4 / 7.1.1 Multiple Vulnerabilities");
  script_summary(english:"Check version of Adobe Reader");

 script_set_attribute(attribute:"synopsis", value:
"The PDF file viewer on the remote Windows host is affected by
multiple vulnerabilities.");

 script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote host is earlier
than 9.1 / 8.1.4 / 7.1.1.  Such versions are reportedly affected by
multiple vulnerabilities :

  - An integer buffer overflow can be triggered when
    processing a malformed JBIG2 image stream with the
    '/JBIG2Decode' filter. (CVE-2009-0658)

  - A vulnerability in the 'getIcon()' JavaScript method of
    a Collab object could allow for remote code execution. 
    (CVE-2009-0927)

  - Additional vulnerabilities involving handling of JBIG2 
    image streams could lead to remote code execution.
    (CVE-2009-0193, CVE-2009-0928, CVE-2009-1061, 
    CVE-2009-1062)

If an attacker can trick a user into opening a specially crafted PDF
file, he can exploit these flaws to execute arbitrary code subject to
the user's privileges.");

 script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb09-03.html" );

 script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb09-04.html");

 script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader 9.1 / 8.1.4 / 7.1.1 or later." );

 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

 script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("adobe_reader_installed.nasl");
  script_require_keys("SMB/Acroread/Version");

  exit(0);
}

include("global_settings.inc");

ver = get_kb_item("SMB/Acroread/Version");
if (
  ver &&
  (
    ver =~ "^[0-6]\." ||
    ver =~ "^7\.(0\.|1\.0\.)" ||
    ver =~ "^8\.(0\.|1\.[0-3]\.)" ||
    ver =~ "^9\.0\."
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
