
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12457);
 script_version ("$Revision: 1.9 $");
 script_name(english: "RHSA-2004-041: slocate");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-041");
 script_set_attribute(attribute: "description", value: '
  Updated slocate packages are now available that fix vulnerabilities
  allowing a local user to gain "slocate" group privileges.

  Slocate is a security-enhanced version of locate, designed to find files on
  a system via a central database.

  Patrik Hornik discovered a vulnerability in Slocate versions up to and
  including 2.7 where a carefully crafted database could overflow a
  heap-based buffer. A local user could exploit this vulnerability to gain
  "slocate" group privileges and then read the entire slocate database. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CAN-2003-0848 to this issue.

  Users of Slocate should upgrade to these erratum packages, which contain
  Slocate version 2.7 with the addition of a patch from Kevin Lindsay that
  causes slocate to drop privileges before reading a user-supplied database.

  For Red Hat Enterprise Linux 2.1 these packages also fix a buffer overflow
  that affected unpatched versions of Slocate prior to 2.7. This
  vulnerability could also allow a local user to gain "slocate" group
  privileges. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2003-0056 to this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-041.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0056", "CVE-2003-0848");
script_summary(english: "Check for the version of the slocate packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"slocate-2.7-1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"slocate-2.7-3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
