#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(31864);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2008-1380");
  script_bugtraq_id(28818);
  script_xref(name:"OSVDB", value:"44467");
  script_xref(name:"Secunia", value:"29787");

  script_name(english:"Firefox < 2.0.0.14 Javascript Garbage Collector DoS ");
  script_summary(english:"Checks version of Firefox");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that may allow
arbitrary code execution." );
 script_set_attribute(attribute:"description", value:
"The installed version of Firefox contains a stability problem that
could result in a crash during JavaScript garbage collection. 
Although there are no examples of this extending beyond a crash,
similar issues in the past have been shown to allow arbitrary code
execution." );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-20.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 2.0.0.14 or later." );
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
  (ver[0] == 2 && ver[1] == 0 && ver[2] == 0 && ver[3] < 14)
) security_hole(get_kb_item("SMB/transport"));
