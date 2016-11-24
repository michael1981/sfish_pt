#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(30209);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2008-0412", "CVE-2008-0413", "CVE-2008-0414", "CVE-2008-0415", "CVE-2008-0416",
                "CVE-2008-0417", "CVE-2008-0418", "CVE-2008-0419", "CVE-2008-0420", "CVE-2008-0591",
                "CVE-2008-0592", "CVE-2008-0593", "CVE-2008-0594");
  script_bugtraq_id(24293, 27406, 27683, 27826, 29303);
  script_xref(name:"OSVDB", value:"41187");
  script_xref(name:"OSVDB", value:"41215");
  script_xref(name:"OSVDB", value:"41217");
  script_xref(name:"OSVDB", value:"41218");
  script_xref(name:"OSVDB", value:"41220");
  script_xref(name:"OSVDB", value:"41221");
  script_xref(name:"OSVDB", value:"41222");
  script_xref(name:"OSVDB", value:"41223");
  script_xref(name:"OSVDB", value:"41224");
  script_xref(name:"OSVDB", value:"41225");
  script_xref(name:"OSVDB", value:"42056");
  script_xref(name:"OSVDB", value:"42057");
  script_xref(name:"OSVDB", value:"43226");
  script_xref(name:"OSVDB", value:"43456");
  script_xref(name:"OSVDB", value:"43457");
  script_xref(name:"OSVDB", value:"43458");
  script_xref(name:"OSVDB", value:"43459");
  script_xref(name:"OSVDB", value:"43460");
  script_xref(name:"OSVDB", value:"43461");
  script_xref(name:"OSVDB", value:"43462");

  script_name(english:"Firefox < 2.0.0.12 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The installed version of Firefox is affected by various security
issues :

  - Several stability bugs leading to crashes which, in
    some cases, show traces of memory corruption

  - Several file input focus stealing vulnerabilities
    that could result in uploading of arbitrary files
    provided their full path and file names are known.

  - Several issues that allow scripts from page content 
    to escape from their sandboxed context and/or run 
    with chrome privileges, resulting in privilege 
    escalation, XSS, and/or remote code execution.

  - An issue that could allow a malicious site to inject
    newlines into the application's password store when
    a user saves his password, resulting in corruption
    of saved passwords for other sites.  

  - A directory traversal vulnerability via the 
    'chrome:' URI.

  - A vulnerability involving 'designMode' frames that
    may result in web browsing history and forward 
    navigation stealing.

  - An information disclosure issue in the BMP 
    decoder.

  - A file action dialog tampering vulnerability
    involving timer-enabled security dialogs.

  - Mis-handling of locally-saved plain text files.

  - Possible disclosure of sensitive URL parameters,
    such as session tokens, via the .href property of 
    stylesheet DOM nodes reflecting the final URI of 
    the stylesheet after following any 302 redirects.

  - A failure to display a web forgery warning 
    dialog in cases where the entire contents of a page 
    are enclosed in a '<div>' with absolute positioning.

  - Multiple cross-site scripting vulnerabilities 
    related to character encoding." );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-01.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-02.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-03.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-04.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-05.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-06.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-07.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-08.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-09.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-10.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-11.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-13.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 2.0.0.12 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");
  exit(0);
}

#

include("misc_func.inc");

ver = read_version_in_kb("Mozilla/Firefox/Version");
if (isnull(ver)) exit(0);

if (
  ver[0] < 2 ||
  (ver[0] == 2 && ver[1] == 0 && ver[2] == 0 && ver[3] < 12)
) security_hole(get_kb_item("SMB/transport"));
