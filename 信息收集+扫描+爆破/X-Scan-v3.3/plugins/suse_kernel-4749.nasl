
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29248);
 script_version ("$Revision: 1.4 $");
 script_name(english: "SuSE Security Update:  Linux Kernel update (kernel-4749)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch kernel-4749");
 script_set_attribute(attribute: "description", value: "This kernel update fixes the following security problems:

++ CVE-2007-5500: A buggy condition in the ptrace attach
 logic can be used by local attackers to hang the machine.

++ CVE-2007-5501: The tcp_sacktag_write_queue function in
 net/ipv4/tcp_input.c allows remote attackers to cause a
 denial of service (crash) via crafted ACK responses that
 trigger a NULL pointer dereference.

++ CVE-2007-5904: Multiple buffer overflows in CIFS VFS
 allows remote attackers to cause a denial of service
 (crash) and possibly execute arbitrary code via long SMB
 responses that trigger the overflows in the SendReceive
 function.

                  This requires the attacker to set up a
malicious Samba/CIFS server and getting the client to
connect to it.

and the following non security bugs:

++ Kernel update to 2.6.22.13 (includes the fixes for
 CVE-2007-5500 and CVE-2007-5501 described above)
++ patches.fixes/input-add-ms-vm-to-noloop.patch: add
 i8042.noloop quirk for Microsoft Virtual Machine  [#297546]
++ patches.fixes/mac80211_fix_scan.diff: Make per-SSID
 scanning work  [#299598] [#327684]
++ patches.drivers/kobil_sct_backport.patch: Fix segfault
 for Kobil USB Plus cardreaders  [#327664]
++ patches.arch/acpi_thermal_passive_blacklist.patch: Avoid
 critical temp shutdowns on specific ThinkPad T4x(p) and
 R40 [#333043]
++ patches.fixes/microtek_hal.diff: Make the microtek
 driver work with HAL  [#339743]
++ patches.fixes/pci-fix-unterminated-pci_device_id-lists:
 fix unterminated pci_device_id lists  [#340527]
++ patches.fixes/nfsacl-retval.diff: knfsd: fix spurious
 EINVAL errors on first access of new filesystem  [#340873]
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:A/AC:H/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch kernel-4749");
script_end_attributes();

script_cve_id("CVE-2007-5500", "CVE-2007-5501", "CVE-2007-5904", "CVE-2007-5500", "CVE-2007-5501");
script_summary(english: "Check for the kernel-4749 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"kernel-bigsmp-2.6.22.13-0.3", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.22.13-0.3", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.22.13-0.3", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-kdump-2.6.22.13-0.3", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-ppc64-2.6.22.13-0.3", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-rt-2.6.22.13-0.3", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-rt_debug-2.6.22.13-0.3", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.22.13-0.3", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.22.13-0.3", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.22.13-0.3", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xenpae-2.6.22.13-0.3", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
