#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(20842);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2005-4134", "CVE-2006-0292", "CVE-2006-0293", "CVE-2006-0294", "CVE-2006-0295",
                "CVE-2006-0296", "CVE-2006-0297", "CVE-2006-0298", "CVE-2006-0299");
  script_bugtraq_id(15773, 16476, 16741);
  script_xref(name:"OSVDB", value:"21533");
  script_xref(name:"OSVDB", value:"22890");
  script_xref(name:"OSVDB", value:"22891");
  script_xref(name:"OSVDB", value:"22892");
  script_xref(name:"OSVDB", value:"22893");
  script_xref(name:"OSVDB", value:"22894");
  script_xref(name:"OSVDB", value:"22895");
  script_xref(name:"OSVDB", value:"22896");
  script_xref(name:"OSVDB", value:"22897");
  script_xref(name:"OSVDB", value:"22898");
  script_xref(name:"OSVDB", value:"22899");

  script_name(english:"Firefox < 1.5.0.1 Multiple Vulnerabilities");
  script_summary(english:"Checks for Firefox < 1.5.0.1");

 script_set_attribute(attribute:"synopsis", value:
"A web browser on the remote host is prone to multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The remote Windows host is using Firefox, an alternative web browser. 

The installed version of Firefox contains various security issues, some
of which can be exploited to execute arbitrary code on the affected host
subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-01.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-02.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-03.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-04.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-05.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-06.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-07.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-08.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/425590/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 1.5.0.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");
  exit(0);
}

#

include("misc_func.inc");

ver = read_version_in_kb("Mozilla/Firefox/Version");
if (isnull(ver)) exit(0);

if (
  ver[0] < 1 ||
  (
    ver[0] == 1 &&
    (
      ver[1] < 5 ||
      (ver[1] == 5 && ver[2] == 0 && ver[3] < 1)
    )
  )
) security_hole(get_kb_item("SMB/transport"));
