
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22058);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2006:123: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2006:123 (kernel).");
 script_set_attribute(attribute: "description", value: "A number of vulnerabilities were discovered and corrected in the Linux
2.6 kernel:
The kernel did not clear sockaddr_in.sin_zero before returning IPv4
socket names for the getsockopt function, which could allow a local
user to obtain portions of potentially sensitive memory if getsockopt()
is called with SO_ORIGINAL_DST (CVE-2006-1343).
Prior to 2.6.16, a buffer overflow in the USB Gadget RNDIS
implementation could allow a remote attacker to cause a Denial of
Service via a remote NDIS response (CVE-2006-1368).
Prior to 2.6.13, local users could cause a Denial of Service (crash)
via a dio transfer from the sg driver to memory mapped IO space
(CVE-2006-1528).
Prior to and including 2.6.16, the kernel did not add the appropriate
LSM file_permission hooks to the readv and writev functions, which
could allow an attacker to bypass intended access restrictions
(CVE-2006-1856).
Prior to 2.6.16.17, a buffer oveflow in SCTP could allow a remote
attacker to cause a DoS (crash) and possibly execute arbitrary code
via a malformed HB-ACK chunk (CVE-2006-1857).
Prior to 2.6.16.17, SCTP could allow a remote attacker to cause a DoS
(crash) and possibly execute arbitrary code via a chunk length that is
inconsistent with the actual length of provided parameters
(CVE-2006-1858).
Prior to 2.6.16.16, a memory leak in fs/locks.c could allow an attacker
to cause a DoS (memory consumption) via unspecified actions
(CVE-2006-1859).
Prior to 2.6.16.16, lease_init in fs/locks.c could allow an attacker to
cause a DoS (fcntl_setlease lockup) via certain actions (CVE-2006-1860).
Prior to 2.6.17, SCTP allowed remote attackers to cause a DoS (infinite
recursion and crash) via a packet that contains two or more DATA
fragments (CVE-2006-2274).
Prior to 2.6.16.21, a race condition in run_posix_cpu timers could allow
a local user to cause a DoS (BUG_ON crash) by causing one CPU to attach
a timer to a process that is exiting (CVE-2006-2445).
Prior to 2.6.17.1, xt_sctp in netfilter could allow an attacker to cause
a DoS (infinite loop) via an SCTP chunk with a 0 length (CVE-2006-3085).
As well, an issue where IPC could hit an unmapped vmalloc page when
near the page boundary has been corrected.
In addition to these security fixes, other fixes have been included
such as:
- avoid automatic update of kernel-source without updating the kernel
- fix USB EHCI handoff code, which made some machines hang while
booting
- disable USB_BANDWIDTH which corrects a known problem in some USB
sound devices
- fix a bluetooth refcounting bug which could hang the machine
- fix a NULL pointer dereference in USB-Serial's serial_open()
function
- add missing wakeup in pl2303 TIOCMIWAIT handling
- fix a possible user-after-free in USB-Serial core
- suspend/resume fixes
- HPET timer fixes
- prevent fixed button event to reach userspace on S3 resume
- add sysfs support in ide-tape
- fix ASUS P5S800 reboot
Finally, a new drbd-utils package is provided that is a required
upgrade with this new kernel due to a logic bug in the previously
shipped version of drbd-utils that could cause a kernel panic on
the master when a slave went offline.
The provided packages are patched to fix these vulnerabilities. All
users are encouraged to upgrade to these updated kernels.
To update your kernel, please follow the directions located at:
http://www.mandriva.com/en/security/kernelupdate
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:123");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2006-1343", "CVE-2006-1368", "CVE-2006-1528", "CVE-2006-1856", "CVE-2006-1857", "CVE-2006-1858", "CVE-2006-1859", "CVE-2006-1860", "CVE-2006-2274", "CVE-2006-2445", "CVE-2006-3085");
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

if ( rpm_check( reference:"drbd-utils-0.7.19-2.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"drbd-utils-heartbeat-0.7.19-2.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.6.12.23mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.6.12.23mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-i586-up-1GB-2.6.12.23mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-i686-up-4GB-2.6.12.23mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.12.23mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.12.23mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-stripped-2.6.12.23mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xbox-2.6.12.23mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen0-2.6.12.23mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-2.6.12.23mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"kernel-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-1343", value:TRUE);
 set_kb_item(name:"CVE-2006-1368", value:TRUE);
 set_kb_item(name:"CVE-2006-1528", value:TRUE);
 set_kb_item(name:"CVE-2006-1856", value:TRUE);
 set_kb_item(name:"CVE-2006-1857", value:TRUE);
 set_kb_item(name:"CVE-2006-1858", value:TRUE);
 set_kb_item(name:"CVE-2006-1859", value:TRUE);
 set_kb_item(name:"CVE-2006-1860", value:TRUE);
 set_kb_item(name:"CVE-2006-2274", value:TRUE);
 set_kb_item(name:"CVE-2006-2445", value:TRUE);
 set_kb_item(name:"CVE-2006-3085", value:TRUE);
}
exit(0, "Host is not affected");
