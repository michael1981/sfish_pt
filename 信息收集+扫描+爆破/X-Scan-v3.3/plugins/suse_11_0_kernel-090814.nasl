
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40783);
 script_version("$Revision: 1.1 $");
 script_name(english: "SuSE 11.0 Security Update:  kernel (2009-08-14)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for kernel");
 script_set_attribute(attribute: "description", value: "This kernel update for openSUSE 11.0 fixes some bugs and
several security problems.

The following security issues are fixed: CVE-2009-2692: A
missing NULL pointer check in the socket sendpage function
can be used by local attackers to gain root privileges.

CVE-2009-2406: A kernel stack overflow when mounting
eCryptfs filesystems in parse_tag_11_packet() was fixed.
Code execution might be possible of ecryptfs is in use.

CVE-2009-2407: A kernel heap overflow when mounting
eCryptfs filesystems in parse_tag_3_packet() was fixed.
Code execution might be possible of ecryptfs is in use.

The compiler option -fno-delete-null-pointer-checks was
added to the kernel build, and the -fwrapv compiler option
usage was fixed to be used everywhere. This works around
the compiler removing checks too aggressively.

CVE-2009-1389: A crash in the r8169 driver when receiving
large packets was fixed. This is probably exploitable only
in the local network.

CVE-2009-1895: Personality flags on set*id were not cleared
correctly, so ASLR and NULL page protection could be
bypassed.

CVE-2009-1046: A utf-8 console memory corruption that can
be used for local privilege escalation was fixed.

The NULL page protection using mmap_min_addr was enabled
(was disabled before).

No CVE yet: A sigaltstack kernel memory disclosure was
fixed.

CVE-2008-5033: A local denial of service (Oops) in
video4linux tvaudio was fixed.

CVE-2009-1385: A Integer underflow in the
e1000_clean_rx_irq function in
drivers/net/e1000/e1000_main.c in the e1000 driver the
e1000e driver in the Linux kernel, and Intel Wired Ethernet
(aka e1000) before 7.5.5 allows remote attackers to cause a
denial of service (panic) via a crafted frame size.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for kernel");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=530151");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=521427");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=527848");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=478699");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=523719");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=522914");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=522686");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=444982");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=474549");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=503870");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=511243");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=509822");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=478462");
script_end_attributes();

 script_cve_id("CVE-2008-5033", "CVE-2009-1046", "CVE-2009-1385", "CVE-2009-1389", "CVE-2009-1895", "CVE-2009-2406", "CVE-2009-2407", "CVE-2009-2692");
script_summary(english: "Check for the kernel package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"acerhk-kmp-debug-0.5.35_2.6.25.20_0.5-98.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"acx-kmp-debug-20080210_2.6.25.20_0.5-3.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"acx-kmp-debug-20080210_2.6.25.20_0.5-3.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"appleir-kmp-debug-1.1_2.6.25.20_0.5-108.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"appleir-kmp-debug-1.1_2.6.25.20_0.5-108.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"at76_usb-kmp-debug-0.17_2.6.25.20_0.5-2.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"at76_usb-kmp-debug-0.17_2.6.25.20_0.5-2.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"atl2-kmp-debug-2.0.4_2.6.25.20_0.5-4.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"atl2-kmp-debug-2.0.4_2.6.25.20_0.5-4.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"aufs-kmp-debug-cvs20080429_2.6.25.20_0.5-13.3", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"aufs-kmp-debug-cvs20080429_2.6.25.20_0.5-13.3", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"dazuko-kmp-debug-2.3.4.4_2.6.25.20_0.5-42.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"dazuko-kmp-debug-2.3.4.4_2.6.25.20_0.5-42.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"drbd-kmp-debug-8.2.6_2.6.25.20_0.5-0.2", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"drbd-kmp-debug-8.2.6_2.6.25.20_0.5-0.2", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"gspcav-kmp-debug-01.00.20_2.6.25.20_0.5-1.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"gspcav-kmp-debug-01.00.20_2.6.25.20_0.5-1.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"iscsitarget-kmp-debug-0.4.15_2.6.25.20_0.5-63.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"iscsitarget-kmp-debug-0.4.15_2.6.25.20_0.5-63.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"ivtv-kmp-debug-1.0.3_2.6.25.20_0.5-66.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"ivtv-kmp-debug-1.0.3_2.6.25.20_0.5-66.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.25.20-0.5", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.25.20-0.5", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.25.20-0.5", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.25.20-0.5", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-docs-2.6.25.20-0.5", release:"SUSE11.0", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-pae-2.6.25.20-0.5", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.25.20-0.5", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.25.20-0.5", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.25.20-0.5", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.25.20-0.5", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-vanilla-2.6.25.20-0.5", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-vanilla-2.6.25.20-0.5", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.25.20-0.5", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.25.20-0.5", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kqemu-kmp-debug-1.3.0pre11_2.6.25.20_0.5-7.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kqemu-kmp-debug-1.3.0pre11_2.6.25.20_0.5-7.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"nouveau-kmp-debug-0.10.1.20081112_2.6.25.20_0.5-0.4", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"nouveau-kmp-debug-0.10.1.20081112_2.6.25.20_0.5-0.4", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"omnibook-kmp-debug-20080313_2.6.25.20_0.5-1.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"omnibook-kmp-debug-20080313_2.6.25.20_0.5-1.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"pcc-acpi-kmp-debug-0.9_2.6.25.20_0.5-4.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"pcc-acpi-kmp-debug-0.9_2.6.25.20_0.5-4.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"pcfclock-kmp-debug-0.44_2.6.25.20_0.5-207.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"pcfclock-kmp-debug-0.44_2.6.25.20_0.5-207.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"tpctl-kmp-debug-4.17_2.6.25.20_0.5-189.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"uvcvideo-kmp-debug-r200_2.6.25.20_0.5-2.4", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"uvcvideo-kmp-debug-r200_2.6.25.20_0.5-2.4", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"virtualbox-ose-kmp-debug-1.5.6_2.6.25.20_0.5-33.3", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"virtualbox-ose-kmp-debug-1.5.6_2.6.25.20_0.5-33.3", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"vmware-kmp-debug-2008.04.14_2.6.25.20_0.5-21.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"vmware-kmp-debug-2008.04.14_2.6.25.20_0.5-21.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"wlan-ng-kmp-debug-0.2.8_2.6.25.20_0.5-107.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"wlan-ng-kmp-debug-0.2.8_2.6.25.20_0.5-107.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");
