
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(26903);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0323: xen");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0323");
 script_set_attribute(attribute: "description", value: '
  An updated Xen package to fix multiple security issues is now available for
  Red Hat Enterprise Linux 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The Xen package contains the tools for managing the virtual machine monitor
  in Red Hat Enterprise Linux virtualization.

  The following security flaws are fixed in the updated Xen package:

  Joris van Rantwijk found a flaw in the Pygrub utility which is used as a
  boot loader for guest domains. A malicious local administrator of a guest
  domain could create a carefully crafted grub.conf file which would trigger
  the execution of arbitrary code outside of that domain. (CVE-2007-4993)

  Tavis Ormandy discovered a heap overflow flaw during video-to-video copy
  operations in the Cirrus VGA extension code used in Xen. A malicious local
  administrator of a guest domain could potentially trigger this flaw and
  execute arbitrary code outside of the domain. (CVE-2007-1320)

  Tavis Ormandy discovered insufficient input validation leading to a heap
  overflow in the Xen NE2000 network driver. If the driver is in use, a
  malicious local administrator of a guest domain could potentially trigger
  this flaw and execute arbitrary code outside of the domain. Xen does not
  use this driver by default. (CVE-2007-1321)

  Users of Xen should update to these erratum packages containing backported
  patches which correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0323.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-1320", "CVE-2007-1321", "CVE-2007-4993");
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

if ( rpm_check( reference:"xen-libs-3.0.3-25.0.4.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
