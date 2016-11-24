#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(31652);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2007-4879", "CVE-2008-1195", "CVE-2008-1233", "CVE-2008-1234", "CVE-2008-1235",
                "CVE-2008-1236", "CVE-2008-1237", "CVE-2008-1238", "CVE-2008-1240", "CVE-2008-1241");
  script_bugtraq_id(28448);
  script_xref(name:"OSVDB", value:"38036");
  script_xref(name:"OSVDB", value:"43846");
  script_xref(name:"OSVDB", value:"43847");
  script_xref(name:"OSVDB", value:"43848");
  script_xref(name:"OSVDB", value:"43849");
  script_xref(name:"OSVDB", value:"43857");
  script_xref(name:"OSVDB", value:"43858");
  script_xref(name:"OSVDB", value:"43859");
  script_xref(name:"OSVDB", value:"43860");
  script_xref(name:"OSVDB", value:"43861");
  script_xref(name:"OSVDB", value:"43862");
  script_xref(name:"OSVDB", value:"43863");
  script_xref(name:"OSVDB", value:"43864");
  script_xref(name:"OSVDB", value:"43865");
  script_xref(name:"OSVDB", value:"43866");
  script_xref(name:"OSVDB", value:"43867");
  script_xref(name:"OSVDB", value:"43868");
  script_xref(name:"OSVDB", value:"43869");
  script_xref(name:"OSVDB", value:"43870");
  script_xref(name:"OSVDB", value:"43871");
  script_xref(name:"OSVDB", value:"43872");
  script_xref(name:"OSVDB", value:"43873");
  script_xref(name:"OSVDB", value:"43874");
  script_xref(name:"OSVDB", value:"43875");
  script_xref(name:"OSVDB", value:"43876");
  script_xref(name:"OSVDB", value:"43877");
  script_xref(name:"OSVDB", value:"43878");

  script_name(english:"Firefox < 2.0.0.13 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The installed version of Firefox is affected by various security
issues :

  - A series of vulnerabilities that allow for JavaScript 
    privilege escalation and arbitrary code execution.

  - Several stability bugs leading to crashes which, in
    some cases, show traces of memory corruption.

  - An HTTP Referer spoofing issue with malformed URLs.

  - A privacy issue with SSL client authentication.

  - Web content fetched via the 'jar:' protocol can use 
    Java via LiveConnect to open socket connections to 
    arbitrary ports on the localhost.

  - It is possible to have a background tab create a 
    border-less XUL pop-up in front of the active tab 
    in the user's browser." );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-14.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-15.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-16.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-17.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-18.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-19.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 2.0.0.13 or later." );
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
  (ver[0] == 2 && ver[1] == 0 && ver[2] == 0 && ver[3] < 13)
) security_hole(get_kb_item("SMB/transport"));
