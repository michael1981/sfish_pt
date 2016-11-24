
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(19992);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-674: perl");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-674");
 script_set_attribute(attribute: "description", value: '
  Updated Perl packages that fix security issues and contain several bug
  fixes are now available for Red Hat Enterprise Linux 4.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  Perl is a high-level programming language commonly used for system
  administration utilities and Web programming.

  Paul Szabo discovered a bug in the way Perl\'s File::Path::rmtree module
  removed directory trees. If a local user has write permissions to a
  subdirectory within the tree being removed by File::Path::rmtree, it is
  possible for them to create setuid binary files. The Common Vulnerabilities
  and Exposures project (cve.mitre.org) has assigned the name CAN-2005-0448
  to this issue.

  This update also addresses the following issues:

  -- Perl interpreter caused a segmentation fault when environment
  changes occurred during runtime.

  -- Code in lib/FindBin contained a regression that caused problems with
  MRTG software package.

  -- Perl incorrectly declared it provides an FCGI interface where it in fact
  did not.

  Users of Perl are advised to upgrade to these updated packages, which
  contain backported patches to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:H/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-674.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-0448");
script_summary(english: "Check for the version of the perl packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"perl-5.8.5-16.RHEL4", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"perl-suidperl-5.8.5-16.RHEL4", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
