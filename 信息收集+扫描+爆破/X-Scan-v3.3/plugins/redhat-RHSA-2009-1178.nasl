
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40402);
 script_version ("$Revision: 1.2 $");
 script_name(english: "RHSA-2009-1178: python");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1178");
 script_set_attribute(attribute: "description", value: '
  Updated python packages that fix multiple security issues are now available
  for Red Hat Enterprise Linux 3.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Python is an interpreted, interactive, object-oriented programming
  language.

  When the assert() system call was disabled, an input sanitization flaw was
  revealed in the Python string object implementation that led to a buffer
  overflow. The missing check for negative size values meant the Python
  memory allocator could allocate less memory than expected. This could
  result in arbitrary code execution with the Python interpreter\'s
  privileges. (CVE-2008-1887)

  Multiple buffer and integer overflow flaws were found in the Python Unicode
  string processing and in the Python Unicode and string object
  implementations. An attacker could use these flaws to cause a denial of
  service (Python application crash). (CVE-2008-3142, CVE-2008-5031)

  Multiple integer overflow flaws were found in the Python imageop module. If
  a Python application used the imageop module to process untrusted images,
  it could cause the application to crash or, potentially, execute arbitrary
  code with the Python interpreter\'s privileges. (CVE-2008-1679,
  CVE-2008-4864)

  Multiple integer underflow and overflow flaws were found in the Python
  snprintf() wrapper implementation. An attacker could use these flaws to
  cause a denial of service (memory corruption). (CVE-2008-3144)

  Multiple integer overflow flaws were found in various Python modules. An
  attacker could use these flaws to cause a denial of service (Python
  application crash). (CVE-2008-2315, CVE-2008-3143)

  Red Hat would like to thank David Remahl of the Apple Product Security team
  for responsibly reporting the CVE-2008-1679 and CVE-2008-2315 issues.

  All Python users should upgrade to these updated packages, which contain
  backported patches to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1178.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-1679", "CVE-2008-1887", "CVE-2008-2315", "CVE-2008-3142", "CVE-2008-3143", "CVE-2008-3144", "CVE-2008-4864", "CVE-2008-5031");
script_summary(english: "Check for the version of the python packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"python-2.2.3-6.11", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"python-devel-2.2.3-6.11", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"python-tools-2.2.3-6.11", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tkinter-2.2.3-6.11", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
