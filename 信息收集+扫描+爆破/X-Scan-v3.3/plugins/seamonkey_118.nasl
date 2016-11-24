#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(30210);
  script_version("$Revision: 1.8 $");

  script_cve_id(
    "CVE-2008-0304",
    "CVE-2008-0412",
    "CVE-2008-0413",
    "CVE-2008-0414",
    "CVE-2008-0415",
    "CVE-2008-0416",
    "CVE-2008-0418",
    "CVE-2008-0419",
    "CVE-2008-0420",
    "CVE-2008-0592",
    "CVE-2008-0593"
  );
  script_bugtraq_id(27406, 27683, 27826, 28012, 29303);
  script_xref(name:"OSVDB", value:"42428");
  script_xref(name:"OSVDB", value:"43226");

  script_name(english:"SeaMonkey < 1.1.8");
  script_summary(english:"Checks version of SeaMonkey");

 script_set_attribute(attribute:"synopsis", value:
"A web browser on the remote host is affected by multiple
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The installed version of SeaMonkey is affected by various security
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

  - A directory traversal vulnerability via the 
    'chrome:' URI.

  - A vulnerability involving 'designMode' frames that
    may result in web browsing history and forward 
    navigation stealing.

  - An information disclosure issue in the BMP 
    decoder.

  - Mis-handling of locally-saved plain text files.

  - Possible disclosure of sensitive URL parameters,
    such as session tokens, via the .href property of 
    stylesheet DOM nodes reflecting the final URI of 
    the stylesheet after following any 302 redirects.

  - A heap buffer overflow that can be triggered
    when viewing an email with an external MIME 
    body.

  - Multiple cross-site scripting vulnerabilities 
    related to character encoding." );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-01.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-02.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-03.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-05.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-06.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-07.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-09.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-10.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-12.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-13.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to SeaMonkey 1.1.8 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
 
  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("SeaMonkey/Version");

  exit(0);
}


include("misc_func.inc");


ver = read_version_in_kb("SeaMonkey/Version");
if (isnull(ver)) exit(0);

if (
  ver[0] < 1 ||
  (
    ver[0] == 1 && 
    (
      ver[1] == 0 ||
      (ver[1] == 1 && ver[2] < 8)
    )
  )
) security_hole(get_kb_item("SMB/transport"));
