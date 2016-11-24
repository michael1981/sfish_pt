
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(34956);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-1001: tog");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-1001");
 script_set_attribute(attribute: "description", value: '
  Updated tog-pegasus packages that fix security issues are now available
  for Red Hat Enterprise Linux 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The tog-pegasus packages provide OpenPegasus Web-Based Enterprise
  Management (WBEM) services. WBEM is a platform and resource independent
  Distributed Management Task Force (DMTF) standard that defines a common
  information model and communication protocol for monitoring and controlling
  resources.

  Red Hat defines additional security enhancements for OpenGroup Pegasus WBEM
  services in addition to those defined by the upstream OpenGroup Pegasus
  release. For details regarding these enhancements, refer to the file
  "README.RedHat.Security", included in the Red Hat tog-pegasus package.

  After re-basing to version 2.7.0 of the OpenGroup Pegasus code, these
  additional security enhancements were no longer being applied. As a
  consequence, access to OpenPegasus WBEM services was not restricted to the
  dedicated users as described in README.RedHat.Security. An attacker able to
  authenticate using a valid user account could use this flaw to send
  requests to WBEM services. (CVE-2008-4313)

  Note: default SELinux policy prevents tog-pegasus from modifying system
  files. This flaw\'s impact depends on whether or not tog-pegasus is confined
  by SELinux, and on any additional CMPI providers installed and enabled on a
  particular system.

  Failed authentication attempts against the OpenPegasus CIM server were not
  logged to the system log as documented in README.RedHat.Security. An
  attacker could use this flaw to perform password guessing attacks against a
  user account without leaving traces in the system log. (CVE-2008-4315)

  All tog-pegasus users are advised to upgrade to these updated packages,
  which contain patches to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-1001.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-4313", "CVE-2008-4315");
script_summary(english: "Check for the version of the tog packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"tog-pegasus-2.7.0-2.el5_2.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tog-pegasus-devel-2.7.0-2.el5_2.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
