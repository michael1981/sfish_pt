
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(31089);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  Linux Kernel update (kernel-4986)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch kernel-4986");
 script_set_attribute(attribute: "description", value: "This kernel update fixes the following security problems:

- CVE-2008-0600: A local privilege escalation was found in
  the vmsplice_pipe system call, which could be used by
  local attackers to gain root access.

- CVE-2007-6206: Core dumps from root might be accessible
  to the wrong owner.


And the following bugs (numbers are
https://bugzilla.novell.com/ references):

- Update to minor kernel version 2.6.22.17
  - networking bugfixes
  - contains the following patches which were removed:
    - patches.arch/acpica-psd.patch
    - patches.fixes/invalid-semicolon
    - patches.fixes/nopage-range-fix.patch

- patches.arch/acpi_thermal_blacklist_add_r50p.patch: Avoid
  critical temp shutdowns on specific Thinkpad R50p
  (https://bugzilla.novell.com/show_bug.cgi?id=333043).

- Update config files. CONFIG_USB_DEBUG in debug kernel

- patches.rt/megasas_IRQF_NODELAY.patch: Convert megaraid
  sas IRQ to non-threaded IRQ (337489).

- patches.drivers/libata-implement-force-parameter added to
  series.conf.

- patches.xen/xen3-fixup-arch-i386: xen3 i386 build fixes.
- patches.xen/xenfb-module-param: Re: Patching Xen virtual
  framebuffer.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch kernel-4986");
script_end_attributes();

script_cve_id("CVE-2008-0600", "CVE-2007-6206");
script_summary(english: "Check for the kernel-4986 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"kernel-bigsmp-2.6.22.17-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.22.17-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.22.17-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-kdump-2.6.22.17-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-ppc64-2.6.22.17-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-rt-2.6.22.17-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-rt_debug-2.6.22.17-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.22.17-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.22.17-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.22.17-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xenpae-2.6.22.17-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
