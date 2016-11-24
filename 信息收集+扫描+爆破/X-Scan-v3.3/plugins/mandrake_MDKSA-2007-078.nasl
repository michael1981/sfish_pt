
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24944);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2007:078: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2007:078 (kernel).");
 script_set_attribute(attribute: "description", value: "Some vulnerabilities were discovered and corrected in the Linux
2.6 kernel:
When SELinux hooks are enabled, the kernel could allow a local user
to cause a DoS (crash) via a malformed file stream that triggers a
NULL pointer derefernece (CVE-2006-6056).
Multiple buffer overflows in the (1) read and (2) write handlers in
the Omnikey CardMan 4040 driver in the Linux kernel before 2.6.21-rc3
allow local users to gain privileges. (CVE-2007-0005)
The Linux kernel version 2.6.13 to 2.6.20.1 allowed a remote attacker to
cause a DoS (oops) via a crafted NFSACL2 ACCESS request that triggered
a free of an incorrect pointer (CVE-2007-0772).
A local user could read unreadable binaries by using the interpreter
(PT_INTERP) functionality and triggering a core dump; a variant of
CVE-2004-1073 (CVE-2007-0958).
The ipv6_getsockopt_sticky function in net/ipv6/ipv6_sockglue.c in the
Linux kernel before 2.6.20.2 allows local users to read arbitrary
kernel memory via certain getsockopt calls that trigger a NULL
dereference. (CVE-2007-1000)
Buffer overflow in the bufprint function in capiutil.c in libcapi,
as used in Linux kernel 2.6.9 to 2.6.20 and isdn4k-utils, allows local
users to cause a denial of service (crash) and possibly gain privileges
via a crafted CAPI packet. (CVE-2007-1217)
The do_ipv6_setsockopt function in net/ipv6/ipv6_sockglue.c in Linux
kernel 2.6.17, and possibly other versions, allows local users to cause
a denial of service (oops) by calling setsockopt with the IPV6_RTHDR
option name and possibly a zero option length or invalid option value,
which triggers a NULL pointer dereference. (CVE-2007-1388)
net/ipv6/tcp_ipv6.c in Linux kernel 2.4 and 2.6.x up to 2.6.21-rc3
inadvertently copies the ipv6_fl_socklist from a listening TCP socket
to child sockets, which allows local users to cause a denial of service
(OOPS) or double-free by opening a listeing IPv6 socket, attaching a
flow label, and connecting to that socket. (CVE-2007-1592)
The provided packages are patched to fix these vulnerabilities.
All users are encouraged to upgrade to these updated kernels immediately
and reboot to effect the fixes.
In addition to these security fixes, other fixes have been included
such as:
- Suspend to disk speed improvements
- Add nmi watchdog support for core2
- Add atl1 driver
- Update KVM
- Add acer_acpi
- Update asus_acpi
- Fix suspend on r8169, i8259A
- Fix suspend when using ondemand governor
- Add ide acpi support
- Add suspend/resume support for sata_nv chipsets.
- USB: Let USB-Serial option driver handle anydata devices (#29066)
- USB: Add PlayStation 2 Trance Vibrator driver
- Fix bogus delay loop in video/aty/mach64_ct.c
- Add MCP61 support (#29398)
- USB: fix floppy drive SAMSUNG SFD-321U/EP detected 8 times bug
- Improve keyboard handling on Apple MacBooks
- Add -latest patch
- Workaround a possible binutils bug in smp alternatives
- Add forcedeth support
- Fix potential deadlock in driver core (USB hangs at boot time
#24683)
To update your kernel, please follow the directions located at:
http://www.mandriva.com/en/security/kernelupdate
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2007:078");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2004-1073", "CVE-2006-6056", "CVE-2007-0005", "CVE-2007-0772", "CVE-2007-0958", "CVE-2007-1000", "CVE-2007-1217", "CVE-2007-1388", "CVE-2007-1592");
script_summary(english: "Check for the version of the kernel package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"kernel-2.6.17.13mdv-1-1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.17.13mdv-1-1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.6.17.13mdv-1-1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-legacy-2.6.17.13mdv-1-1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.17.13mdv-1-1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-stripped-2.6.17.13mdv-1-1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen0-2.6.17.13mdv-1-1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-2.6.17.13mdv-1-1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"kernel-", release:"MDK2007.0") )
{
 set_kb_item(name:"CVE-2004-1073", value:TRUE);
 set_kb_item(name:"CVE-2006-6056", value:TRUE);
 set_kb_item(name:"CVE-2007-0005", value:TRUE);
 set_kb_item(name:"CVE-2007-0772", value:TRUE);
 set_kb_item(name:"CVE-2007-0958", value:TRUE);
 set_kb_item(name:"CVE-2007-1000", value:TRUE);
 set_kb_item(name:"CVE-2007-1217", value:TRUE);
 set_kb_item(name:"CVE-2007-1388", value:TRUE);
 set_kb_item(name:"CVE-2007-1592", value:TRUE);
}
exit(0, "Host is not affected");
