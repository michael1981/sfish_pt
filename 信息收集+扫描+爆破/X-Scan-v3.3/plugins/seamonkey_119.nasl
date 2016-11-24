#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(31653);
  script_version("$Revision: 1.3 $");

  script_cve_id(
    "CVE-2007-4879",
    "CVE-2008-1195",
    "CVE-2008-1233",
    "CVE-2008-1234",
    "CVE-2008-1235",
    "CVE-2008-1236",
    "CVE-2008-1237",
    "CVE-2008-1238",
    "CVE-2008-1240",
    "CVE-2008-1241"
  );
  script_bugtraq_id(28448);

  script_name(english:"SeaMonkey < 1.1.9");
  script_summary(english:"Checks version of SeaMonkey");

 script_set_attribute(attribute:"synopsis", value:
"A web browser on the remote host is affected by multiple
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The installed version of SeaMonkey is affected by various security
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
"Upgrade to SeaMonkey 1.1.9 or later." );
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
      (ver[1] == 1 && ver[2] < 9)
    )
  )
) security_hole(get_kb_item("SMB/transport"));
