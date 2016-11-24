#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3004) exit(1);


include("compat.inc");

if (description)
{
  script_id(29744);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-4134", "CVE-2006-0292", "CVE-2006-0296", "CVE-2006-0748", "CVE-2006-0749",
                "CVE-2006-1727", "CVE-2006-1728", "CVE-2006-1729", "CVE-2006-1730", "CVE-2006-1731",
                "CVE-2006-1732", "CVE-2006-1733", "CVE-2006-1734", "CVE-2006-1735", "CVE-2006-1736",
                "CVE-2006-1737", "CVE-2006-1738", "CVE-2006-1739", "CVE-2006-1740", "CVE-2006-1741",
                "CVE-2006-1742", "CVE-2006-1790");
  script_bugtraq_id(15773, 16476, 17516);
  script_xref(name:"OSVDB", value:"21533");
  script_xref(name:"OSVDB", value:"22890");
  script_xref(name:"OSVDB", value:"22892");
  script_xref(name:"OSVDB", value:"22894");
  script_xref(name:"OSVDB", value:"24658");
  script_xref(name:"OSVDB", value:"24659");
  script_xref(name:"OSVDB", value:"24660");
  script_xref(name:"OSVDB", value:"24661");
  script_xref(name:"OSVDB", value:"24662");
  script_xref(name:"OSVDB", value:"24663");
  script_xref(name:"OSVDB", value:"24664");
  script_xref(name:"OSVDB", value:"24665");
  script_xref(name:"OSVDB", value:"24666");
  script_xref(name:"OSVDB", value:"24667");
  script_xref(name:"OSVDB", value:"24668");
  script_xref(name:"OSVDB", value:"24669");
  script_xref(name:"OSVDB", value:"24670");
  script_xref(name:"OSVDB", value:"24671");
  script_xref(name:"OSVDB", value:"24677");
  script_xref(name:"OSVDB", value:"24678");
  script_xref(name:"OSVDB", value:"24679");
  script_xref(name:"OSVDB", value:"24680");
  script_xref(name:"OSVDB", value:"24947");

  script_name(english:"Firefox < 1.0.8 Multiple Vulnerabilities");
  script_summary(english:"Checks Firefox version number");

 script_set_attribute(attribute:"synopsis", value:
"A web browser on the remote host is prone to multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The installed version of Firefox contains various security issues,
some of which may lead to execution of arbitrary code on the affected
host subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-01.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-03.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-05.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-09.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-10.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-11.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-12.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-13.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-14.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-15.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-16.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-17.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-18.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-19.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-22.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-23.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-24.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-25.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-27.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 1.0.8 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
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
  (ver[0] == 1 && ver[1] == 0 && ver[2] < 8)
) security_hole(get_kb_item("SMB/transport"));
