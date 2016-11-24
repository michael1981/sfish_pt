#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(21225);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2006-0748", "CVE-2006-1529", "CVE-2006-1530", "CVE-2006-1531", "CVE-2006-1723",
                "CVE-2006-1724", "CVE-2006-1725", "CVE-2006-1726", "CVE-2006-1727", "CVE-2006-1728",
                "CVE-2006-1729", "CVE-2006-1730");
  script_bugtraq_id(17516);
  script_xref(name:"OSVDB", value:"24672");
  script_xref(name:"OSVDB", value:"24673");
  script_xref(name:"OSVDB", value:"24674");
  script_xref(name:"OSVDB", value:"24675");
  script_xref(name:"OSVDB", value:"24676");
  script_xref(name:"OSVDB", value:"24677");
  script_xref(name:"OSVDB", value:"24678");
  script_xref(name:"OSVDB", value:"24679");
  script_xref(name:"OSVDB", value:"24680");
  script_xref(name:"OSVDB", value:"24682");
  script_xref(name:"OSVDB", value:"24683");
  script_xref(name:"OSVDB", value:"24947");

  script_name(english:"Firefox < 1.5.0.2 Multiple Vulnerabilities");
  script_summary(english:"Checks Firefox version number");

 script_set_attribute(attribute:"synopsis", value:
"A web browser on the remote host is prone to multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The remote Windows host is using Firefox, an alternative web browser. 

The installed version of Firefox contains various security issues,
some of which may lead to execution of arbitrary code on the affected
host subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-20.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-22.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-23.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-24.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-25.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-27.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-28.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-29.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 1.5.0.2 or later." );
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

if (ver[0] == 1 && ver[1] == 5 && ver[2] == 0 && ver[3] < 2)
  security_hole(get_kb_item("SMB/transport"));
