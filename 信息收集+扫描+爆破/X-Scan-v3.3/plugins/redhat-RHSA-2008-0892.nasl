
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(34329);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2008-0892: xen");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0892");
 script_set_attribute(attribute: "description", value: '
  Updated xen packages that resolve a couple of security issues and fix a bug
  are now available for Red Hat Enterprise Linux 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The xen packages contain tools for managing the virtual machine monitor in
  Red Hat Virtualization.

  It was discovered that the hypervisor\'s para-virtualized framebuffer (PVFB)
  backend failed to validate the frontend\'s framebuffer description properly.
  This could allow a privileged user in the unprivileged domain (DomU) to
  cause a denial of service, or, possibly, elevate privileges to the
  privileged domain (Dom0). (CVE-2008-1952)

  A flaw was found in the QEMU block format auto-detection, when running
  fully-virtualized guests and using Qemu images written on removable media
  (USB storage, 3.5" disks). Privileged users of such fully-virtualized
  guests (DomU), with a raw-formatted disk image, were able to write a header
  to that disk image describing another format. This could allow such guests
  to read arbitrary files in their hypervisor\'s host (Dom0). (CVE-2008-1945)

  Additionally, the following bug is addressed in this update:

  * The qcow-create command terminated when invoked due to glibc bounds
  checking on the realpath() function.

  Users of xen are advised to upgrade to these updated packages, which
  resolve these security issues and fix this bug.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0892.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-1945", "CVE-2008-1952");
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

if ( rpm_check( reference:"xen-libs-3.0.3-64.el5_2.3", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
