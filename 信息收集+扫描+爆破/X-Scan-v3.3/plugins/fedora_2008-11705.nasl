
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-11705
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(35266);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2008-11705: kvm");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-11705 (kvm)");
 script_set_attribute(attribute: "description", value: "KVM (for Kernel-based Virtual Machine) is a full virtualization solution
for Linux on x86 hardware.

Using KVM, one can run multiple virtual machines running unmodified Linux
or Windows images. Each virtual machine has private virtualized hardware:
a network card, disk, graphics adapter, etc.

-
Update Information:


");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-2382", "CVE-2008-4539");
script_summary(english: "Check for the version of the kvm package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"kvm-65-15.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
