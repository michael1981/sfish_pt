#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(17603);
 script_version("$Revision: 1.18 $");

 script_cve_id("CVE-2005-0399", "CVE-2005-0401", "CVE-2005-0402");
 script_bugtraq_id(12672, 12881, 12884, 12885);
 script_xref(name:"OSVDB", value:"14937");
 script_xref(name:"OSVDB", value:"15009");
 script_xref(name:"OSVDB", value:"15010");

 script_name(english:"Firefox < 1.0.2 Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote version of Firefox contains various security issues that
may allow an attacker to impersonate a website and to trick a user
into accepting and executing arbitrary files or to cause a heap
overflow in the FireFox process and execute arbitrary code on the
remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2005/mfsa2005-30.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2005/mfsa2005-31.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2005/mfsa2005-32.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 1.0.2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 script_summary(english:"Determines the version of Firefox");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows");
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
  (ver[0] == 1 && ver[1] == 0 && ver[2] < 2)
) security_warning(get_kb_item("SMB/transport"));
