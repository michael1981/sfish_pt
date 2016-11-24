
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-2057
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(31313);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 8 2008-2057: xen");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-2057 (xen)");
 script_set_attribute(attribute: "description", value: "This package contains the Xen hypervisor and Xen tools, needed to
run virtual machines on x86 systems, together with the kernel-xen*
packages.  Information on how to use Xen can be found at the Xen
project pages.

Virtualisation can be used to run multiple versions or multiple
Linux distributions on one system, or to test untrusted applications
in a sandboxed environment.

-
ChangeLog:


Update information :

* Sat Feb 23 2008 Daniel P. Berrange <berrange redhat com> - 3.1.2-2.fc8
- Fix block device extents check (rhbz #433560)
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the xen package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"xen-3.1.2-2.fc8", release:"FC8") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
