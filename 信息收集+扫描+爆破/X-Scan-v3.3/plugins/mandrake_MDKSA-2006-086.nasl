
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21575);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2006:086: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2006:086 (kernel).");
 script_set_attribute(attribute: "description", value: "A number of vulnerabilities were discovered and corrected in the Linux
2.6 kernel:
Prior to Linux kernel 2.6.16.5, the kernel does not properly handle
uncanonical return addresses on Intel EM64T CPUs which causes the
kernel exception handler to run on the user stack with the wrong GS
(CVE-2006-0744).
The selinux_ptrace logic hooks in SELinux for 2.6.6 allow local users
with ptrace permissions to change the tracer SID to an SID of another
process (CVE-2006-1052).
Prior to 2.6.16, the ip_push_pending_frames function increments the IP
ID field when sending a RST after receiving unsolicited TCP SYN-ACK
packets, which allows a remote attacker to conduct an idle scan attack,
bypassing any intended protection against such an attack
(CVE-2006-1242).
In kernel 2.6.16.1 and some earlier versions, the sys_add_key function
in the keyring code allows local users to cause a DoS (OOPS) via keyctl
requests that add a key to a user key instead of a keyring key, causing
an invalid dereference (CVE-2006-1522).
Prior to 2.6.16.8, the ip_route_input function allows local users to
cause a DoS (panic) via a request for a route for a multicast IP
address, which triggers a null dereference (CVE-2006-1525).
Prior to 2.6.16.13, the SCTP-netfilter code allows remote attackers to
cause a DoS (infinite loop) via unknown vectors that cause an invalid
SCTP chunk size to be processed (CVE-2006-1527).
Prior to 2.6.16, local users can bypass IPC permissions and modify a
read-only attachment of shared memory by using mprotect to give write
permission to the attachment (CVE-2006-2071).
Prior to 2.6.17, the ECNE chunk handling in SCTP (lksctp) allows remote
attackers to cause a DoS (kernel panic) via an unexpected chucnk when
the session is in CLOSED state (CVE-2006-2271).
Prior to 2.6.17, SCTP (lksctp) allows remote attacker to cause a DoS
(kernel panic) via incoming IP fragmented COOKIE_ECHO and HEARTBEAT
SCTP control chunks (CVE-2006-2272).
In addition to these security fixes, other fixes have been included
such as:
- fix a scheduler deadlock
- Yenta oops fix
- ftdi_sio: adds support for iPlus devices
- enable kprobes on i386 and x86_64
- avoid a panic on bind mount of autofs owned directory
- fix a kernel OOPs when booting with 'console=ttyUSB0' but without a
USB-serial dongle plugged in
- make dm-mirror not issue invalid resync requests
- fix media change detection on scsi removable devices
- add support for the realtek 8168 chipset
- update hfsplus driver to 2.6.16 state
- backport 'Gilgal' support from e1000 7.0.33
- selected ACPI video fixes
- update 3w-9xxx to 2.26.02.005 (9550SX support)
- fix a deadlock in the ext2 filesystem
- fix usbserial use-after-free bug
- add i945GM DRI support
- S3 resume fixes
- add ECS PF22 hda model support
- SMP suspend
- CPU hotplug
- miscellaneous AGP fixes
- added sata-suspend patch for 2.6.12 for Napa platform
The provided packages are patched to fix these vulnerabilities. All
users are encouraged to upgrade to these updated kernels.
As well, updated mkinitrd and bootsplash packages are provided to fix
minor issues; users should upgrade both packages prior to installing
a new kernel.
To update your kernel, please follow the directions located at:
http://www.mandriva.com/en/security/kernelupdate
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:086");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2006-0744", "CVE-2006-1052", "CVE-2006-1242", "CVE-2006-1522", "CVE-2006-1525", "CVE-2006-1527", "CVE-2006-2071", "CVE-2006-2271", "CVE-2006-2272");
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

if ( rpm_check( reference:"bootsplash-3.1.12-0.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.6.12.21mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.6.12.21mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-i586-up-1GB-2.6.12.21mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-i686-up-4GB-2.6.12.21mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.12.21mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6-2.6.12-21mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-stripped-2.6-2.6.12-21mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xbox-2.6.12.21mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen0-2.6.12.21mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-2.6.12.21mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mkinitrd-4.2.17-17.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"kernel-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-0744", value:TRUE);
 set_kb_item(name:"CVE-2006-1052", value:TRUE);
 set_kb_item(name:"CVE-2006-1242", value:TRUE);
 set_kb_item(name:"CVE-2006-1522", value:TRUE);
 set_kb_item(name:"CVE-2006-1525", value:TRUE);
 set_kb_item(name:"CVE-2006-1527", value:TRUE);
 set_kb_item(name:"CVE-2006-2071", value:TRUE);
 set_kb_item(name:"CVE-2006-2271", value:TRUE);
 set_kb_item(name:"CVE-2006-2272", value:TRUE);
}
exit(0, "Host is not affected");
