#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(24701);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2006-6077", "CVE-2007-0008", "CVE-2007-0009", "CVE-2007-0775", "CVE-2007-0776",
                "CVE-2007-0777", "CVE-2007-0778", "CVE-2007-0779", "CVE-2007-0780", "CVE-2007-0800",
                "CVE-2007-0801", "CVE-2007-0802", "CVE-2007-0981", "CVE-2007-0994", "CVE-2007-0995",
                "CVE-2007-0996", "CVE-2007-1092");
  script_bugtraq_id(21240, 22396, 22566, 22679, 22694, 22826);
  script_xref(name:"OSVDB", value:"30641");
  script_xref(name:"OSVDB", value:"32103");
  script_xref(name:"OSVDB", value:"32104");
  script_xref(name:"OSVDB", value:"32105");
  script_xref(name:"OSVDB", value:"32106");
  script_xref(name:"OSVDB", value:"32107");
  script_xref(name:"OSVDB", value:"32108");
  script_xref(name:"OSVDB", value:"32110");
  script_xref(name:"OSVDB", value:"32111");
  script_xref(name:"OSVDB", value:"32113");
  script_xref(name:"OSVDB", value:"32114");
  script_xref(name:"OSVDB", value:"32115");
  script_xref(name:"OSVDB", value:"33811");
  script_xref(name:"OSVDB", value:"33812");

  script_name(english:"Firefox < 1.5.0.10 / 2.0.0.2 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The installed version of Firefox is affected by various security
issues, some of which may lead to execution of arbitrary code on the
affected host subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-01.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-02.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-03.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-04.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-05.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-06.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-07.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-08.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-09.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 1.5.0.10 / 2.0.0.2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

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
  (
    ver[0] == 1 &&
    (
      ver[1] < 5 ||
      (ver[1] == 5 && ver[2] == 0 && ver[3] < 10)
    ) 
  ) ||
  (ver[0] == 2 && ver[1] == 0 && ver[2] == 0 && ver[3] < 2)
) security_hole(get_kb_item("SMB/transport"));
