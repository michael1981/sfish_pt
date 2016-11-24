#
# (C) Tenable Network Security, Inc.
#


if (NASL_LEVEL < 3004) exit(0);



include("compat.inc");

if (description)
{
  script_id(35581);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2009-0352", "CVE-2009-0353", "CVE-2009-0354", "CVE-2009-0355", "CVE-2009-0356",
                "CVE-2009-0357", "CVE-2009-0358");
  script_bugtraq_id(33598);
  script_xref(name:"OSVDB", value:"51925");
  script_xref(name:"OSVDB", value:"51926");
  script_xref(name:"OSVDB", value:"51927");
  script_xref(name:"OSVDB", value:"51928");
  script_xref(name:"OSVDB", value:"51929");
  script_xref(name:"OSVDB", value:"51930");
  script_xref(name:"OSVDB", value:"51931");
  script_xref(name:"OSVDB", value:"51932");
  script_xref(name:"OSVDB", value:"51933");
  script_xref(name:"OSVDB", value:"51934");
  script_xref(name:"OSVDB", value:"51935");
  script_xref(name:"OSVDB", value:"51936");
  script_xref(name:"OSVDB", value:"51937");
  script_xref(name:"OSVDB", value:"51938");
  script_xref(name:"OSVDB", value:"51939");
  script_xref(name:"OSVDB", value:"51940");

  script_name(english:"Firefox < 3.0.6 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The installed version of Firefox is earlier than 3.0.6.  Such versions
are potentially affected by the following security issues :

  - There are several stability bugs in the browser engine
    that may lead to crashes with evidence of memory 
    corruption. (MFSA 2009-01)

  - A chrome XBL method can be used in conjunction with 
    'window.eval' to execute arbitrary JavaScript within 
    the context of another website, violating the same 
    origin policy. (MFSA 2009-02)

  - A form input control's type could be changed during the
    restoration of a closed tab to the path of a local file
    whose location was known to the attacker. 
    (MFSA 2009-03)

  - An attacker may be able to inject arbitrary code into a
    chrome document and then execute it with chrome 
    privileges if he can trick a user into downloading a 
    malicious HTML file and a .desktop shortcut file. 
    (MFSA 2009-04)

  - Cookies marked HTTPOnly are readable by JavaScript via
    the 'XMLHttpRequest.getResponseHeader' and 
    'XMLHttpRequest.getAllResponseHeaders' APIs. 
    (MFSA 2009-05)

  - The 'Cache-Control: no-store' and 'Cache-Control: 
    no-cache' HTTP directives for HTTPS pages are ignored 
    by Firefox 3, which could lead to exposure of 
    sensitive information. (MFSA 2009-06)" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-01.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-02.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-03.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-04.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-05.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-06.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 3.0.6 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");
  exit(0);
}

#

include("misc_func.inc");

ver = read_version_in_kb("Mozilla/Firefox/Version");
if (isnull(ver)) exit(0);

if (
  ver[0] < 3 ||
  (ver[0] == 3 && ver[1] == 0 && ver[2] < 6)
) security_hole(get_kb_item("SMB/transport"));
