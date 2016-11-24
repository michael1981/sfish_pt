#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(35218);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2008-5500", "CVE-2008-5503", "CVE-2008-5504", "CVE-2008-5506", "CVE-2008-5507",
                "CVE-2008-5508", "CVE-2008-5510", "CVE-2008-5511", "CVE-2008-5512", "CVE-2008-5513",
                "CVE-2009-2535");
  script_bugtraq_id(32882, 35446);
  script_xref(name:"OSVDB", value:"51284");
  script_xref(name:"OSVDB", value:"51285");
  script_xref(name:"OSVDB", value:"51288");
  script_xref(name:"OSVDB", value:"51289");
  script_xref(name:"OSVDB", value:"51291");
  script_xref(name:"OSVDB", value:"51292");
  script_xref(name:"OSVDB", value:"51293");
  script_xref(name:"OSVDB", value:"51294");
  script_xref(name:"OSVDB", value:"51295");
  script_xref(name:"OSVDB", value:"51296");
  script_xref(name:"OSVDB", value:"51297");
  script_xref(name:"OSVDB", value:"56253");

  script_name(english:"Firefox < 2.0.0.19 / 3.0.5 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The installed version of Firefox is earlier than 2.0.0.19.  Such
versions are potentially affected by the following security issues :

  - There are several stability bugs in the browser engine
    that may lead to crashes with evidence of memory 
    corruption. (MFSA 2008-60)

  - XBL bindings can be used to read data from other 
    domains. (MFSA 2008-61)

  - The feed preview still allows for JavaScript privilege
    escalation. (MFSA 2008-62)

  - Sensitive data may be disclosed in an XHR response when
    an XMLHttpRequest is made to a same-origin resource,
    which 302 redirects to a resource in a different 
    domain. (MFSA 2008-64)

  - A website may be able to access a limited amount of 
    data from a different domain by loading a same-domain 
    JavaScript URL which redirects to an off-domain target
    resource containing data which is not parsable as 
    JavaScript. (MFSA 2008-65)

  - Errors arise when parsing URLs with leading whitespace
    and control characters. (MFSA 2008-66)

  - An escaped null byte is ignored by the CSS parser and 
    treated as if it was not present in the CSS input 
    string. (MFSA 2008-67)

  - XSS and JavaScript privilege escalation are possible.
    (MFSA 2008-68)

  - XSS vulnerabilities in SessionStore may allow for
    violating the browser's same-origin policy and 
    performing an XSS attack or running arbitrary 
    JavaScript with chrome privileges. (MFSA 2008-69)

  - Creating a Select object with a very large length can
    result in memory exhaustion, causing a denial of
    service. (CVE-2009-2535)

Note that Mozilla is not planning further security / stability
updates for Firefox 2." );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-60.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-61.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-62.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-64.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-65.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-66.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-67.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-68.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-69.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/504969/100/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9e442733" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 2.0.0.19 / 3.0.5 or later." );
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
  (ver[0] == 2 && ver[1] == 0 && ver[2] == 0 && ver[3] < 19)
) security_hole(get_kb_item("SMB/transport"));
