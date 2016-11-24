
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(22223);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0605: perl");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0605");
 script_set_attribute(attribute: "description", value: '
  Updated Perl packages that fix security a security issue are now available
  for Red Hat Enterprise Linux 4.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  Perl is a high-level programming language commonly used for system
  administration utilities and Web programming.

  Kevin Finisterre discovered a flaw in sperl, the Perl setuid wrapper, which
  can cause debugging information to be logged to arbitrary files. By setting
  an environment variable, a local user could cause sperl to create, as root,
  files with arbitrary filenames, or append the debugging information to
  existing files. (CVE-2005-0155)

  A fix for this issue was first included in the update RHSA-2005:103
  released in February 2005. However the patch to correct this issue was
  dropped from the update RHSA-2005:674 made in October 2005. This
  regression has been assigned CVE-2006-3813.

  Users of Perl are advised to upgrade to these updated packages, which
  contain a backported patch to correct this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0605.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-3813");
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

if ( rpm_check( reference:"perl-5.8.5-36.RHEL4", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"perl-suidperl-5.8.5-36.RHEL4", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
