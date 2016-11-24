
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(16367);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-104: mod_python");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-104");
 script_set_attribute(attribute: "description", value: '
  An Updated mod_python package that fixes a security issue in the publisher
  handler is now available.

  Mod_python is a module that embeds the Python language interpreter within
  the Apache web server, allowing handlers to be written in Python.

  Graham Dumpleton discovered a flaw affecting the publisher handler of
  mod_python, used to make objects inside modules callable via URL.
  A remote user could visit a carefully crafted URL that would gain access to
  objects that should not be visible, leading to an information leak. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CAN-2005-0088 to this issue.

  Users of mod_python are advised to upgrade to this updated package,
  which contains a backported patch to correct this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-104.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-0088");
script_summary(english: "Check for the version of the mod_python packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"mod_python-2.7.8-3.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mod_python-3.0.3-5.ent", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
