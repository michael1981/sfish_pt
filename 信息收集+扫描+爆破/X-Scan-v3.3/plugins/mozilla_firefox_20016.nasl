#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(33505);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2008-2785", "CVE-2008-2933");
  script_bugtraq_id(29802, 30242);
  script_xref(name:"OSVDB", value:"46421");
  script_xref(name:"OSVDB", value:"47465");

  script_name(english:"Firefox < 2.0.0.16 / 3.0.1 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The installed version of Firefox is affected by various security
issues :

  - By creating a very large number of references to a 
    common CSS object, an attacker can overflow the CSS
    reference counter, causing a crash when the browser 
    attempts to free the CSS object while still in use
    and allowing for arbitrary code execution
    (MFSA 2008-34).

  - If Firefox is not already running, passing it a
    command-line URI with pipe ('|') symbols will open 
    multiple tabs, which could be used to launch 
    'chrome:i' URIs from the command-line or to pass URIs
    to Firefox that would normally be handled by a vector 
    application (MFSA 2008-35)." );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-34.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-35.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 2.0.0.16 / 3.0.1 or later." );
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
  (ver[0] == 2 && ver[1] == 0 && ver[2] == 0 && ver[3] < 16)
) security_hole(get_kb_item("SMB/transport"));
