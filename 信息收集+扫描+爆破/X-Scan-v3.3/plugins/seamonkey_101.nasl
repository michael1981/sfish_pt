#
# (C) Tenable Network Security
#



include("compat.inc");

if (description)
{
  script_id(21226);
  script_version("$Revision: 1.10 $");

  script_cve_id(
    "CVE-2006-0748",
    "CVE-2006-0749",
    "CVE-2006-0884",
    "CVE-2006-1529",
    "CVE-2006-1530",
    "CVE-2006-1531",
    "CVE-2006-1723",
    "CVE-2006-1724",
    "CVE-2006-1725",
    "CVE-2006-1726",
    "CVE-2006-1727",
    "CVE-2006-1728",
    "CVE-2006-1729",
    "CVE-2006-1730",
    "CVE-2006-1731",
    "CVE-2006-1732",
    "CVE-2006-1733",
    "CVE-2006-1734",
    "CVE-2006-1735",
    "CVE-2006-1736",
    "CVE-2006-1737",
    "CVE-2006-1738",
    "CVE-2006-1739",
    "CVE-2006-1740",
    "CVE-2006-1790"
  );
  script_bugtraq_id(17516);
  script_xref(name:"OSVDB", value:"24947");

  script_name(english:"SeaMonkey < 1.0.1");
  script_summary(english:"Checks version of SeaMonkey");

 script_set_attribute(attribute:"synopsis", value:
"A web browser on the remote host is prone to multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The remote Windows host is using SeaMonkey, an alternative web browser
and application suite. 

The installed version of SeaMonkey contains various security issues,
some of which may lead to execution of arbitrary code on the affected
host subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-20.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-21.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-22.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-23.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-24.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-25.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-27.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-28.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-29.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to SeaMonkey 1.0.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
 
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
 
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("SeaMonkey/Version");

  exit(0);
}


include("misc_func.inc");


ver = read_version_in_kb("SeaMonkey/Version");
if (isnull(ver)) exit(0);

if (
  ver[0] < 1 ||
  (ver[0] == 1 && ver[1] == 0 && ver[2] < 1)
) security_hole(get_kb_item("SMB/transport"));
