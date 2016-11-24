
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27292);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  Kernel Update for SUSE Linux 10.1 (kernel-2635)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch kernel-2635");
 script_set_attribute(attribute: "description", value: "This kernel update fixes the following security problems:

- CVE-2006-2936: The ftdi_sio driver allowed local users to
  cause a denial of service (memory consumption) by writing
  more data to the serial port than the hardware can
  handle, which causes the data to be queued. This requires
  this driver to be  loaded, which only happens if such a
  device is plugged in. [#191836]

- CVE-2006-4814: A deadlock in mincore that could be caused
  by local  attackers was fixed. [#207667]

- CVE-2006-6106: Multiple buffer overflows in the
  cmtp_recv_interopmsg function in the Bluetooth driver
  (net/bluetooth/cmtp/capi.c) in the Linux kernel allowed
  remote attackers to cause a denial of service (crash) and
  possibly execute arbitrary code via CAPI messages with a
  large value for the length of the (1) manu (manufacturer)
  or (2) serial (serial number) field. [#227603]

- CVE-2006-5749: The isdn_ppp_ccp_reset_alloc_state
  function in drivers/isdn/isdn_ppp.c in the Linux kernel
  does not call the init_timer function for the ISDN PPP
  CCP reset state timer, which has unknown attack vectors
  and results in a system crash. [#229619]

- CVE-2006-5753: Unspecified vulnerability in the listxattr
  system call in Linux kernel, when a 'bad inode' is
  present, allows local users to cause a denial of service
  (data corruption) and possibly gain privileges. [#230270]

-                A remote denial of service problem on
NFSv3 mounts with ACL enabled was fixed. [#244909]


Furthermore, this kernel catches up to the SLE 10 state of
the kernel, with massive additional fixes.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch kernel-2635");
script_end_attributes();

script_cve_id("CVE-2006-2936", "CVE-2006-4814", "CVE-2006-6106", "CVE-2006-5749", "CVE-2006-5753");
script_summary(english: "Check for the kernel-2635 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"kernel-bigsmp-2.6.16.27-0.9", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.16.27-0.9", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.16.27-0.9", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-iseries64-2.6.16.27-0.9", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-kdump-2.6.16.27-0.9", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-ppc64-2.6.16.27-0.9", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.16.27-0.9", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.16.27-0.9", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.16.27-0.9", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-um-2.6.16.27-0.9", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.16.27-0.9", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xenpae-2.6.16.27-0.9", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kexec-tools-1.101-32.22.1", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mkinitrd-1.2-106.27.2", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"multipath-tools-0.4.6-25.18", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"open-iscsi-0.5.545-9.17", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"udev-085-30.18.1", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
