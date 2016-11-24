
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-343
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24882);
 script_version ("$Revision: 1.4 $");
script_name(english: "Fedora 6 2007-343: xen");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-343 (xen)");
 script_set_attribute(attribute: "description", value: "This package contains the Xen hypervisor and Xen tools, needed to
run virtual machines on x86 systems, together with the kernel-xen*
packages.  Information on how to use Xen can be found at the Xen
project pages.

Virtualisation can be used to run multiple versions or multiple
Linux distributions on one system, or to test untrusted applications
in a sandboxed environment.

Update Information:

A flaw was found affecting the VNC server code in QEMU. On a
fullyvirtualized guest VM, where qemu monitor mode is
enabled, a user who had access to the VNC server could gain
the ability to read arbitrary files as root in the host
filesystem. (CVE-2007-0998)

");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-0998");
script_summary(english: "Check for the version of the xen package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"xen-libs-3.0.3-8.fc6", release:"FC6") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xen-devel-3.0.3-8.fc6", release:"FC6") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xen-3.0.3-8.fc6", release:"FC6") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
