
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25321);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0114: xen");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0114");
 script_set_attribute(attribute: "description", value: '
  An updated Xen package to fix one security issue and two bugs is now
  available for Red Hat Enterprise Linux 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The Xen package contains the tools for managing the virtual machine monitor
  in Red Hat Enterprise Linux virtualization.

  A flaw was found affecting the VNC server code in QEMU. On a
  fullyvirtualized guest VM, where qemu monitor mode is enabled, a user who
  had access to the VNC server could gain the ability to read arbitrary files
  as root in the host filesystem. (CVE-2007-0998)

  In addition to disabling qemu monitor mode, the following bugs were also
  fixed:

  * Fix IA64 fully virtualized (VTi) shadow page table mode initialization.

  * Fix network bonding in balanced-rr mode. Without this update, a network
  path loss could result in packet loss.

  Users of Xen should update to these erratum packages containing backported
  patches which correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0114.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-0998");
script_summary(english: "Check for the version of the xen packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"xen-libs-3.0.3-25.0.3.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
