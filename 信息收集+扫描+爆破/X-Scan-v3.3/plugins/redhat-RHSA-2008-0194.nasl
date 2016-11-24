
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(32354);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0194: xen");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0194");
 script_set_attribute(attribute: "description", value: '
  Updated xen packages that fix several security issues and a bug are now
  available for Red Hat Enterprise Linux 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The xen packages contain tools for managing the virtual machine monitor in
  Red Hat Virtualization.

  These updated packages fix the following security issues:

  Daniel P. Berrange discovered that the hypervisor\'s para-virtualized
  framebuffer (PVFB) backend failed to validate the format of messages
  serving to update the contents of the framebuffer. This could allow a
  malicious user to cause a denial of service, or compromise the privileged
  domain (Dom0). (CVE-2008-1944)

  Markus Armbruster discovered that the hypervisor\'s para-virtualized
  framebuffer (PVFB) backend failed to validate the frontend\'s framebuffer
  description. This could allow a malicious user to cause a denial of
  service, or to use a specially crafted frontend to compromise the
  privileged domain (Dom0). (CVE-2008-1943)

  Chris Wright discovered a security vulnerability in the QEMU block format
  auto-detection, when running fully-virtualized guests. Such
  fully-virtualized guests, with a raw formatted disk image, were able
  to write a header to that disk image describing another format. This could
  allow such guests to read arbitrary files in their hypervisor\'s host.
  (CVE-2008-2004)

  Ian Jackson discovered a security vulnerability in the QEMU block device
  drivers backend. A guest operating system could issue a block device
  request and read or write arbitrary memory locations, which could lead to
  privilege escalation. (CVE-2008-0928)

  Tavis Ormandy found that QEMU did not perform adequate sanity-checking of
  data received via the "net socket listen" option. A malicious local
  administrator of a guest domain could trigger this flaw to potentially
  execute arbitrary code outside of the domain. (CVE-2007-5730)

  Steve Kemp discovered that the xenbaked daemon and the XenMon utility
  communicated via an insecure temporary file. A malicious local
  administrator of a guest domain could perform a symbolic link attack,
  causing arbitrary files to be truncated. (CVE-2007-3919)

  As well, in the previous xen packages, it was possible for Dom0 to fail to
  flush data from a fully-virtualized guest to disk, even if the guest
  explicitly requested the flush. This could cause data integrity problems on
  the guest. In these updated packages, Dom0 always respects the request to
  flush to disk.

  Users of xen are advised to upgrade to these updated packages, which
  resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0194.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-3919", "CVE-2007-5730", "CVE-2008-0928", "CVE-2008-1943", "CVE-2008-1944", "CVE-2008-2004");
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

if ( rpm_check( reference:"xen-libs-3.0.3-41.el5_1.5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
