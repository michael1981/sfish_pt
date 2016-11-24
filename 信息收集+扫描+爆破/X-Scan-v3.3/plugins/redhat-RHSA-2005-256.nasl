
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(18312);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-256: glibc");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-256");
 script_set_attribute(attribute: "description", value: '
  Updated glibc packages that address several bugs are now available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  The GNU libc packages (known as glibc) contain the standard C libraries
  used by applications.

  It was discovered that the use of LD_DEBUG, LD_SHOW_AUXV, and
  LD_DYNAMIC_WEAK were not restricted for a setuid program. A local user
  could utilize this flaw to gain information, such as the list of symbols
  used by the program. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2004-1453 to this issue.

  This erratum addresses the following bugs in the GNU C Library:

  - fix stack alignment in IA-32 clone
  - fix double free in globfree
  - fix fnmatch to avoid jumping based on unitialized memory read
  - fix fseekpos after ungetc
  - fix TZ env var handling if the variable ends with + or -
  - avoid depending on values read from unitialized memory in strtold
  on certain architectures
  - fix mapping alignment computation in dl-load
  - fix i486+ strncat inline assembly
  - make gethostid/sethostid work on bi-arch platforms
  - fix ppc64 getcontext/swapcontext
  - fix pthread_exit if called after pthread_create, but before the created
  thread actually started
  - fix return values for tgamma (+-0)
  - fix handling of very long lines in /etc/hosts
  - avoid page aliasing of thread stacks on AMD64
  - avoid busy loop in malloc if concurrent with fork
  - allow putenv and setenv in shared library constructors
  - fix restoring of CCR in swapcontext and getcontext on ppc64
  - avoid using sigaction (SIGPIPE, ...) in syslog implementation

  All users of glibc should upgrade to these updated packages, which resolve
  these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-256.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-1453");
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

if ( rpm_check( reference:"glibc-2.3.2-95.33", release:'RHEL3') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"glibc-common-2.3.2-95.33", release:'RHEL3') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"glibc-devel-2.3.2-95.33", release:'RHEL3') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"glibc-headers-2.3.2-95.33", release:'RHEL3') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"glibc-profile-2.3.2-95.33", release:'RHEL3') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"glibc-utils-2.3.2-95.33", release:'RHEL3') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nptl-devel-2.3.2-95.33", release:'RHEL3') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nscd-2.3.2-95.33", release:'RHEL3') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
