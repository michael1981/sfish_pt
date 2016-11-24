
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25877);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0765: libgtop");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0765");
 script_set_attribute(attribute: "description", value: '
  An updated libgtop2 package that fixes a security issue and a functionality
  bug is now available for Red Hat Enterprise Linux 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The libgtop2 package contains a library for obtaining information about a
  running system, such as cpu, memory and disk usage; active processes; and
  PIDs.

  A flaw was found in the way libgtop2 handled long filenames mapped
  into the address space of a process. An attacker could execute arbitrary
  code on behalf of the user running gnome-system-monitor by executing a
  process and mapping a file with a specially crafted name into the
  processes\' address space. (CVE-2007-0235)

  This update also fixes the following bug:

  * when a version of libgtop2 compiled to run on a 32-bit architecture was
  used to inspect a process running in 64-bit mode, it failed to report
  certain information regarding address space mapping correctly.

  All users of gnome-system-monitor are advised to upgrade to this updated
  libgtop2 package, which contains backported patches that resolve these
  issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0765.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-0235");
script_summary(english: "Check for the version of the libgtop packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libgtop2-2.8.0-1.0.2", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgtop2-devel-2.8.0-1.0.2", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
