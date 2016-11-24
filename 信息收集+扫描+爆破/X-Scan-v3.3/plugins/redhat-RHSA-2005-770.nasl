
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(20047);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-770: libuser");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-770");
 script_set_attribute(attribute: "description", value: '
  Updated libuser packages that fix various security issues are now
  available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  The libuser library implements a standardized interface for manipulating
  and administering user and group accounts. The library uses pluggable
  back-ends to interface to its data sources. Sample applications that are
  modeled after applications from the shadow password suite are included in
  the package.

  Several denial of service bugs were discovered in libuser. Under certain
  conditions it is possible for an application linked against libuser to
  crash or operate irregularly. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CAN-2004-2392 to these
  issues.

  All users of libuser are advised to upgrade to these updated packages,
  which contain a backported fix and are not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-770.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-2392");
script_summary(english: "Check for the version of the libuser packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libuser-0.32-1.el2.1", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libuser-devel-0.32-1.el2.1", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
