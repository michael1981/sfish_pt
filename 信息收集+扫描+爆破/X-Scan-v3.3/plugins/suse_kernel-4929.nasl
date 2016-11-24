
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if (NASL_LEVEL < 3000 ) exit(0);

if(description)
{
 script_id(30142);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  Linux Kernel security update. (kernel-4929)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch kernel-4929");
 script_set_attribute(attribute: "description", value: "This kernel update fixes the following security problems:

CVE-2008-0007: Insufficient range checks in certain fault
handlers could be used by local attackers to potentially
read or write kernel memory.

CVE-2008-0001: Incorrect access mode checks could be used
by local attackers to corrupt directory contents and so
cause denial of service attacks or potentially execute code.

CVE-2007-5966: Integer overflow in the hrtimer_start
function in kernel/hrtimer.c in the Linux kernel before
2.6.23.10 allows local users to execute arbitrary code or
cause a denial of service (panic) via a large relative
timeout value. NOTE: some of these details are obtained
from third party information.

CVE-2007-3843: The Linux kernel checked the wrong global
variable for the CIFS sec mount option, which might allow
remote attackers to spoof CIFS network traffic that the
client configured for security signatures, as demonstrated
by lack of signing despite sec=ntlmv2i in a SetupAndX
request.

CVE-2007-2242: The IPv6 protocol allows remote attackers to
cause a denial of service via crafted IPv6 type 0 route
headers (IPV6_RTHDR_TYPE_0) that create network
amplification between two routers.

CVE-2007-6417: The shmem_getpage function (mm/shmem.c) in
Linux kernel 2.6.11 through 2.6.23 does not properly clear
allocated memory in some rare circumstances, which might
allow local users to read sensitive kernel data or cause a
denial of service (crash).

CVE-2007-4308: The (1) aac_cfg_open and (2)
aac_compat_ioctl functions in the SCSI layer ioctl path in
aacraid in the Linux kernel did not check permissions for
ioctls, which might have allowed local users to cause a
denial of service or gain privileges.

CVE-2007-3740: The CIFS filesystem, when Unix extension
support is enabled, does not honor the umask of a process,
which allows local users to gain privileges.

CVE-2007-3848: The Linux kernel allowed local users to send
arbitrary signals to a child process that is running at
higher privileges by causing a setuid-root parent process
to die, which delivers an attacker-controlled parent
process death signal (PR_SET_PDEATHSIG).

CVE-2007-4997: Integer underflow in the ieee80211_rx
function in net/ieee80211/ieee80211_rx.c in the Linux
kernel allowed remote attackers to cause a denial of
service (crash) via a crafted SKB length value in a runt
IEEE 802.11 frame when the IEEE80211_STYPE_QOS_DATA flag is
set, aka an 'off-by-two error.'

CVE-2007-6063: Buffer overflow in the isdn_net_setcfg
function in isdn_net.c in the Linux kernel allowed local
users to have an unknown impact via a crafted argument to
the isdn_ioctl function.

CVE-none-yet: A failed change_hat call can result in an
apparmored task becoming unconfined (326546).

and the following non security bugs:
- patches.suse/apparmor-r206-310260.diff: AppArmor - add
  audit capability names (310260).
- patches.suse/apparmor-r326-240982.diff: AppArmor - fix
  memory corruption if policy load fails (240982).
- patches.suse/apparmor-r400-221567.diff: AppArmor - kernel
  dead locks when audit back log occurs (221567).
- patches.suse/apparmor-r405-247679.diff: AppArmor -
  apparmor fails to log link reject in complain mode
  (247679).
- patches.suse/apparmor-r473-326556.diff: AppArmor - fix
  race on ambiguous deleted file name (326556).
- patches.suse/apparmor-r479-257748.diff: AppArmor - fix
  kernel crash that can occur on profile removal (257748).
- patches.fixes/usb_unusual_292931.diff: add quirk needed
  for 1652:6600 (292931).
- patches.drivers/r8169-perform-a-PHY-reset-before.patch:
  r8169: perform a PHY reset before any other operation at
  boot time (345658).
- patches.drivers/r8169-more-alignment-for-the-0x8168:
  refresh.
- patches.fixes/usb_336850.diff: fix missing quirk leading
  to a device disconnecting under load (336850).
- patches.fixes/avm-fix-capilib-locking: [ISDN] Fix random
  hard freeze with AVM cards. (#341894)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch kernel-4929");
script_end_attributes();

script_cve_id("CVE-2008-0007", "CVE-2008-0001", "CVE-2007-5966", "CVE-2007-3843", "CVE-2007-2242", "CVE-2007-6417", "CVE-2007-4308", "CVE-2007-3740", "CVE-2007-3848", "CVE-2007-4997", "CVE-2007-6063");
script_summary(english: "Check for the kernel-4929 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"kernel-bigsmp-2.6.18.8-0.8", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.18.8-0.8", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-iseries64-2.6.18.8-0.8", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-kdump-2.6.18.8-0.8", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-ppc64-2.6.18.8-0.8", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.18.8-0.8", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.18.8-0.8", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.18.8-0.8", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xenpae-2.6.18.8-0.8", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
