
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12490);
 script_version ("$Revision: 1.9 $");
 script_name(english: "RHSA-2004-174: utempter");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-174");
 script_set_attribute(attribute: "description", value: '
  An updated utempter package that fixes a potential symlink vulnerability is
  now available.

  Utempter is a utility that allows terminal applications such as xterm and
  screen to update utmp and wtmp without requiring root privileges.

  Steve Grubb discovered a flaw in Utempter which allowed device names
  containing directory traversal sequences such as \'/../\'. In combination
  with an application that trusts the utmp or wtmp files, this could allow a
  local attacker the ability to overwrite privileged files using a symlink.

  Users should upgrade to this new version of utempter, which fixes this
  vulnerability.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-174.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0233");
script_summary(english: "Check for the version of the utempter packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"utempter-0.5.5-1.2.1EL.0", release:'RHEL2.1') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"utempter-0.5.5-1.3EL.0", release:'RHEL3') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
