
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(14212);
 script_version ("$Revision: 1.10 $");
 script_name(english: "RHSA-2004-383: glibc");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-383");
 script_set_attribute(attribute: "description", value: '
  Updated glibc packages that fix a security flaw in the resolver as well as
  dlclose handling are now available.

  The GNU libc packages (known as glibc) contain the standard C libraries
  used by applications.

  A security audit of the glibc packages in Red Hat Enterprise Linux 2.1
  found a flaw in the resolver library which was originally reported as
  affecting versions of ISC BIND 4.9. This flaw also applied to glibc
  versions before 2.3.2. An attacker who is able to send DNS responses
  (perhaps by creating a malicious DNS server) could remotely exploit this
  vulnerability to execute arbitrary code or cause a denial of service. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CAN-2002-0029 to this issue.

  These updated packages also fix a dlclose function bug on certain shared
  libraries, which caused program crashes.

  All users of glibc should upgrade to these updated packages, which
  resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-383.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2002-0029");
script_summary(english: "Check for the version of the glibc packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"glibc-2.2.4-32.17", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"glibc-common-2.2.4-32.17", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"glibc-devel-2.2.4-32.17", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"glibc-profile-2.2.4-32.17", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nscd-2.2.4-32.17", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
