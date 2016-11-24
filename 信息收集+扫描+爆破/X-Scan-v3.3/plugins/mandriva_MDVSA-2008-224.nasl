
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37851);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2008:224-1: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:224-1 (kernel).");
 script_set_attribute(attribute: "description", value: "Some vulnerabilities were discovered and corrected in the Linux
2.6 kernel:
The error-reporting functionality in (1) fs/ext2/dir.c, (2)
fs/ext3/dir.c, and possibly (3) fs/ext4/dir.c in the Linux kernel
2.6.26.5 does not limit the number of printk console messages that
report directory corruption, which allows physically proximate
attackers to cause a denial of service (temporary system hang) by
mounting a filesystem that has corrupted dir->i_size and dir->i_blocks
values and performing (a) read or (b) write operations. NOTE:
there are limited scenarios in which this crosses privilege
boundaries. (CVE-2008-3528)
The i915 driver in (1) drivers/char/drm/i915_dma.c in the Linux kernel
2.6.24 on Debian GNU/Linux and (2) sys/dev/pci/drm/i915_drv.c in
OpenBSD does not restrict the DRM_I915_HWS_ADDR ioctl to the Direct
Rendering Manager (DRM) master, which allows local users to cause
a denial of service (memory corruption) via a crafted ioctl call,
related to absence of the DRM_MASTER and DRM_ROOT_ONLY flags in the
ioctl's configuration. (CVE-2008-3831)
The do_splice_from function in fs/splice.c in the Linux kernel before
2.6.27 does not reject file descriptors that have the O_APPEND flag
set, which allows local users to bypass append mode and make arbitrary
changes to other locations in the file. (CVE-2008-4554)
Additionaly, a problem with TCP options ordering, which could manifest
as connection problems with many websites (bug #43372), was solved, a
number of fixes for Intel HDA were added, another number of fixes for
issues on Asus EEE PC, Panasonic Let's Note, Acer One, Dell XPS, and
others, were also added. Check package changelog for more information.
To update your kernel, please follow the directions located at:
http://www.mandriva.com/en/security/kernelupdate
Update:
The previous update included a patch which introduced a bug that would
make the boot process to stop halfway in several machines. That patch
has been removed in this new update, to avoid that problem.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:224-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-3528", "CVE-2008-3831", "CVE-2008-4554");
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

if ( rpm_check( reference:"alsa_raoppcm-kernel-2.6.27.4-desktop-2mnb-0.5.1-2mdv2008.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"alsa_raoppcm-kernel-2.6.27.4-desktop586-2mnb-0.5.1-2mdv2008.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"alsa_raoppcm-kernel-2.6.27.4-server-2mnb-0.5.1-2mdv2008.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"alsa_raoppcm-kernel-desktop586-latest-0.5.1-1.20081106.2mdv2008.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"alsa_raoppcm-kernel-desktop-latest-0.5.1-1.20081106.2mdv2008.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"alsa_raoppcm-kernel-server-latest-0.5.1-1.20081106.2mdv2008.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"drm-experimental-kernel-2.6.27.4-desktop-2mnb-2.3.0-2.20080912.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"drm-experimental-kernel-2.6.27.4-desktop586-2mnb-2.3.0-2.20080912.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"drm-experimental-kernel-2.6.27.4-server-2mnb-2.3.0-2.20080912.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"drm-experimental-kernel-desktop586-latest-2.3.0-1.20081106.2.20080912.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"drm-experimental-kernel-desktop-latest-2.3.0-1.20081106.2.20080912.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"drm-experimental-kernel-server-latest-2.3.0-1.20081106.2.20080912.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"et131x-kernel-2.6.27.4-desktop-2mnb-1.2.3-7mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"et131x-kernel-2.6.27.4-desktop586-2mnb-1.2.3-7mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"et131x-kernel-2.6.27.4-server-2mnb-1.2.3-7mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"et131x-kernel-desktop586-latest-1.2.3-1.20081106.7mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"et131x-kernel-desktop-latest-1.2.3-1.20081106.7mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"et131x-kernel-server-latest-1.2.3-1.20081106.7mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fcpci-kernel-2.6.27.4-desktop-2mnb-3.11.07-7mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fcpci-kernel-2.6.27.4-desktop586-2mnb-3.11.07-7mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fcpci-kernel-2.6.27.4-server-2mnb-3.11.07-7mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fcpci-kernel-desktop586-latest-3.11.07-1.20081106.7mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fcpci-kernel-desktop-latest-3.11.07-1.20081106.7mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fcpci-kernel-server-latest-3.11.07-1.20081106.7mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fglrx-kernel-2.6.27.4-desktop-2mnb-8.522-3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fglrx-kernel-2.6.27.4-desktop586-2mnb-8.522-3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fglrx-kernel-2.6.27.4-server-2mnb-8.522-3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fglrx-kernel-desktop586-latest-8.522-1.20081106.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fglrx-kernel-desktop-latest-8.522-1.20081106.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fglrx-kernel-server-latest-8.522-1.20081106.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gnbd-kernel-2.6.27.4-desktop-2mnb-2.03.07-2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gnbd-kernel-2.6.27.4-desktop586-2mnb-2.03.07-2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gnbd-kernel-2.6.27.4-server-2mnb-2.03.07-2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gnbd-kernel-desktop586-latest-2.03.07-1.20081106.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gnbd-kernel-desktop-latest-2.03.07-1.20081106.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gnbd-kernel-server-latest-2.03.07-1.20081106.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hcfpcimodem-kernel-2.6.27.4-desktop-2mnb-1.17-1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hcfpcimodem-kernel-2.6.27.4-desktop586-2mnb-1.17-1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hcfpcimodem-kernel-2.6.27.4-server-2mnb-1.17-1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hcfpcimodem-kernel-desktop586-latest-1.17-1.20081106.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hcfpcimodem-kernel-desktop-latest-1.17-1.20081106.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hcfpcimodem-kernel-server-latest-1.17-1.20081106.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hsfmodem-kernel-2.6.27.4-desktop-2mnb-7.68.00.13-1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hsfmodem-kernel-2.6.27.4-desktop586-2mnb-7.68.00.13-1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hsfmodem-kernel-2.6.27.4-server-2mnb-7.68.00.13-1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hsfmodem-kernel-desktop586-latest-7.68.00.13-1.20081106.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hsfmodem-kernel-desktop-latest-7.68.00.13-1.20081106.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hsfmodem-kernel-server-latest-7.68.00.13-1.20081106.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hso-kernel-2.6.27.4-desktop-2mnb-1.2-2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hso-kernel-2.6.27.4-desktop586-2mnb-1.2-2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hso-kernel-2.6.27.4-server-2mnb-1.2-2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hso-kernel-desktop586-latest-1.2-1.20081106.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hso-kernel-desktop-latest-1.2-1.20081106.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hso-kernel-server-latest-1.2-1.20081106.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"iscsitarget-kernel-2.6.27.4-desktop-2mnb-0.4.16-4mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"iscsitarget-kernel-2.6.27.4-desktop586-2mnb-0.4.16-4mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"iscsitarget-kernel-2.6.27.4-server-2mnb-0.4.16-4mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"iscsitarget-kernel-desktop586-latest-0.4.16-1.20081106.4mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"iscsitarget-kernel-desktop-latest-0.4.16-1.20081106.4mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"iscsitarget-kernel-server-latest-0.4.16-1.20081106.4mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.6.27.4-2mnb-1-1mnb2", release:"MDK2009.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-desktop-2.6.27.4-2mnb-1-1mnb2", release:"MDK2009.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-desktop586-2.6.27.4-2mnb-1-1mnb2", release:"MDK2009.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-desktop586-devel-2.6.27.4-2mnb-1-1mnb2", release:"MDK2009.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-desktop586-devel-latest-2.6.27.4-2mnb2", release:"MDK2009.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-desktop586-latest-2.6.27.4-2mnb2", release:"MDK2009.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-desktop-devel-2.6.27.4-2mnb-1-1mnb2", release:"MDK2009.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-desktop-devel-latest-2.6.27.4-2mnb2", release:"MDK2009.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-desktop-latest-2.6.27.4-2mnb2", release:"MDK2009.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.27.4-2mnb2", release:"MDK2009.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-server-2.6.27.4-2mnb-1-1mnb2", release:"MDK2009.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-server-devel-2.6.27.4-2mnb-1-1mnb2", release:"MDK2009.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-server-devel-latest-2.6.27.4-2mnb2", release:"MDK2009.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-server-latest-2.6.27.4-2mnb2", release:"MDK2009.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.27.4-2mnb-1-1mnb2", release:"MDK2009.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-latest-2.6.27.4-2mnb2", release:"MDK2009.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kqemu-kernel-2.6.27.4-desktop-2mnb-1.4.0pre1-0", release:"MDK2009.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kqemu-kernel-2.6.27.4-desktop586-2mnb-1.4.0pre1-0", release:"MDK2009.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kqemu-kernel-2.6.27.4-server-2mnb-1.4.0pre1-0", release:"MDK2009.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kqemu-kernel-desktop586-latest-1.4.0pre1-1.20081106.0", release:"MDK2009.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kqemu-kernel-desktop-latest-1.4.0pre1-1.20081106.0", release:"MDK2009.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kqemu-kernel-server-latest-1.4.0pre1-1.20081106.0", release:"MDK2009.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"lirc-kernel-2.6.27.4-desktop-2mnb-0.8.3-4.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"lirc-kernel-2.6.27.4-desktop586-2mnb-0.8.3-4.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"lirc-kernel-2.6.27.4-server-2mnb-0.8.3-4.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"lirc-kernel-desktop586-latest-0.8.3-1.20081106.4.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"lirc-kernel-desktop-latest-0.8.3-1.20081106.4.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"lirc-kernel-server-latest-0.8.3-1.20081106.4.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"lzma-kernel-2.6.27.4-desktop-2mnb-4.43-24mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"lzma-kernel-2.6.27.4-desktop586-2mnb-4.43-24mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"lzma-kernel-2.6.27.4-server-2mnb-4.43-24mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"lzma-kernel-desktop586-latest-4.43-1.20081106.24mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"lzma-kernel-desktop-latest-4.43-1.20081106.24mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"lzma-kernel-server-latest-4.43-1.20081106.24mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"madwifi-kernel-2.6.27.4-desktop-2mnb-0.9.4-3.r3835mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"madwifi-kernel-2.6.27.4-desktop586-2mnb-0.9.4-3.r3835mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"madwifi-kernel-2.6.27.4-server-2mnb-0.9.4-3.r3835mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"madwifi-kernel-desktop586-latest-0.9.4-1.20081106.3.r3835mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"madwifi-kernel-desktop-latest-0.9.4-1.20081106.3.r3835mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"madwifi-kernel-server-latest-0.9.4-1.20081106.3.r3835mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nvidia173-kernel-2.6.27.4-desktop-2mnb-173.14.12-4mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nvidia173-kernel-2.6.27.4-desktop586-2mnb-173.14.12-4mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nvidia173-kernel-desktop586-latest-173.14.12-1.20081106.4mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nvidia173-kernel-desktop-latest-173.14.12-1.20081106.4mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nvidia71xx-kernel-2.6.27.4-desktop-2mnb-71.86.06-5mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nvidia71xx-kernel-2.6.27.4-desktop586-2mnb-71.86.06-5mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nvidia71xx-kernel-2.6.27.4-server-2mnb-71.86.06-5mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nvidia71xx-kernel-desktop586-latest-71.86.06-1.20081106.5mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nvidia71xx-kernel-desktop-latest-71.86.06-1.20081106.5mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nvidia71xx-kernel-server-latest-71.86.06-1.20081106.5mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nvidia96xx-kernel-2.6.27.4-desktop-2mnb-96.43.07-5mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nvidia96xx-kernel-2.6.27.4-desktop586-2mnb-96.43.07-5mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nvidia96xx-kernel-2.6.27.4-server-2mnb-96.43.07-5mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nvidia96xx-kernel-desktop586-latest-96.43.07-1.20081106.5mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nvidia96xx-kernel-desktop-latest-96.43.07-1.20081106.5mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nvidia96xx-kernel-server-latest-96.43.07-1.20081106.5mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nvidia-current-kernel-2.6.27.4-desktop-2mnb-177.70-2.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nvidia-current-kernel-2.6.27.4-desktop586-2mnb-177.70-2.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nvidia-current-kernel-2.6.27.4-server-2mnb-177.70-2.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nvidia-current-kernel-desktop586-latest-177.70-1.20081106.2.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nvidia-current-kernel-desktop-latest-177.70-1.20081106.2.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nvidia-current-kernel-server-latest-177.70-1.20081106.2.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"omfs-kernel-2.6.27.4-desktop-2mnb-0.8.0-1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"omfs-kernel-2.6.27.4-desktop586-2mnb-0.8.0-1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"omfs-kernel-2.6.27.4-server-2mnb-0.8.0-1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"omfs-kernel-desktop586-latest-0.8.0-1.20081106.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"omfs-kernel-desktop-latest-0.8.0-1.20081106.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"omfs-kernel-server-latest-0.8.0-1.20081106.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"omnibook-kernel-2.6.27.4-desktop-2mnb-20080513-0.274.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"omnibook-kernel-2.6.27.4-desktop586-2mnb-20080513-0.274.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"omnibook-kernel-2.6.27.4-server-2mnb-20080513-0.274.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"omnibook-kernel-desktop586-latest-20080513-1.20081106.0.274.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"omnibook-kernel-desktop-latest-20080513-1.20081106.0.274.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"omnibook-kernel-server-latest-20080513-1.20081106.0.274.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"opencbm-kernel-2.6.27.4-desktop-2mnb-0.4.2a-1mdv2008.1", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"opencbm-kernel-2.6.27.4-desktop586-2mnb-0.4.2a-1mdv2008.1", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"opencbm-kernel-2.6.27.4-server-2mnb-0.4.2a-1mdv2008.1", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"opencbm-kernel-desktop586-latest-0.4.2a-1.20081106.1mdv2008.1", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"opencbm-kernel-desktop-latest-0.4.2a-1.20081106.1mdv2008.1", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"opencbm-kernel-server-latest-0.4.2a-1.20081106.1mdv2008.1", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ov51x-jpeg-kernel-2.6.27.4-desktop-2mnb-1.5.8-1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ov51x-jpeg-kernel-2.6.27.4-desktop586-2mnb-1.5.8-1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ov51x-jpeg-kernel-2.6.27.4-server-2mnb-1.5.8-1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ov51x-jpeg-kernel-desktop586-latest-1.5.8-1.20081106.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ov51x-jpeg-kernel-desktop-latest-1.5.8-1.20081106.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ov51x-jpeg-kernel-server-latest-1.5.8-1.20081106.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"qc-usb-kernel-2.6.27.4-desktop-2mnb-0.6.6-6mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"qc-usb-kernel-2.6.27.4-desktop586-2mnb-0.6.6-6mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"qc-usb-kernel-2.6.27.4-server-2mnb-0.6.6-6mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"qc-usb-kernel-desktop586-latest-0.6.6-1.20081106.6mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"qc-usb-kernel-desktop-latest-0.6.6-1.20081106.6mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"qc-usb-kernel-server-latest-0.6.6-1.20081106.6mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rt2860-kernel-2.6.27.4-desktop-2mnb-1.7.0.0-2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rt2860-kernel-2.6.27.4-desktop586-2mnb-1.7.0.0-2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rt2860-kernel-2.6.27.4-server-2mnb-1.7.0.0-2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rt2860-kernel-desktop586-latest-1.7.0.0-1.20081106.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rt2860-kernel-desktop-latest-1.7.0.0-1.20081106.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rt2860-kernel-server-latest-1.7.0.0-1.20081106.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rt2870-kernel-2.6.27.4-desktop-2mnb-1.3.1.0-2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rt2870-kernel-2.6.27.4-desktop586-2mnb-1.3.1.0-2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rt2870-kernel-2.6.27.4-server-2mnb-1.3.1.0-2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rt2870-kernel-desktop586-latest-1.3.1.0-1.20081106.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rt2870-kernel-desktop-latest-1.3.1.0-1.20081106.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rt2870-kernel-server-latest-1.3.1.0-1.20081106.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rtl8187se-kernel-2.6.27.4-desktop-2mnb-1016.20080716-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rtl8187se-kernel-2.6.27.4-desktop586-2mnb-1016.20080716-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rtl8187se-kernel-2.6.27.4-server-2mnb-1016.20080716-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rtl8187se-kernel-desktop586-latest-1016.20080716-1.20081106.1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rtl8187se-kernel-desktop-latest-1016.20080716-1.20081106.1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rtl8187se-kernel-server-latest-1016.20080716-1.20081106.1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"slmodem-kernel-2.6.27.4-desktop-2mnb-2.9.11-0.20080817.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"slmodem-kernel-2.6.27.4-desktop586-2mnb-2.9.11-0.20080817.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"slmodem-kernel-2.6.27.4-server-2mnb-2.9.11-0.20080817.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"slmodem-kernel-desktop586-latest-2.9.11-1.20081106.0.20080817.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"slmodem-kernel-desktop-latest-2.9.11-1.20081106.0.20080817.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"slmodem-kernel-server-latest-2.9.11-1.20081106.0.20080817.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"squashfs-lzma-kernel-2.6.27.4-desktop-2mnb-3.3-5mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"squashfs-lzma-kernel-2.6.27.4-desktop586-2mnb-3.3-5mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"squashfs-lzma-kernel-2.6.27.4-server-2mnb-3.3-5mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"squashfs-lzma-kernel-desktop586-latest-3.3-1.20081106.5mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"squashfs-lzma-kernel-desktop-latest-3.3-1.20081106.5mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"squashfs-lzma-kernel-server-latest-3.3-1.20081106.5mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tp_smapi-kernel-2.6.27.4-desktop-2mnb-0.37-2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tp_smapi-kernel-2.6.27.4-desktop586-2mnb-0.37-2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tp_smapi-kernel-2.6.27.4-server-2mnb-0.37-2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tp_smapi-kernel-desktop586-latest-0.37-1.20081106.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tp_smapi-kernel-desktop-latest-0.37-1.20081106.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tp_smapi-kernel-server-latest-0.37-1.20081106.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vboxadd-kernel-2.6.27.4-desktop-2mnb-2.0.2-2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vboxadd-kernel-2.6.27.4-desktop586-2mnb-2.0.2-2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vboxadd-kernel-2.6.27.4-server-2mnb-2.0.2-2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vboxadd-kernel-desktop586-latest-2.0.2-1.20081106.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vboxadd-kernel-desktop-latest-2.0.2-1.20081106.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vboxadd-kernel-server-latest-2.0.2-1.20081106.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vboxvfs-kernel-2.6.27.4-desktop-2mnb-2.0.2-2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vboxvfs-kernel-2.6.27.4-desktop586-2mnb-2.0.2-2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vboxvfs-kernel-2.6.27.4-server-2mnb-2.0.2-2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vboxvfs-kernel-desktop586-latest-2.0.2-1.20081106.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vboxvfs-kernel-desktop-latest-2.0.2-1.20081106.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vboxvfs-kernel-server-latest-2.0.2-1.20081106.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vhba-kernel-2.6.27.4-desktop-2mnb-1.0.0-1.svn304.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vhba-kernel-2.6.27.4-desktop586-2mnb-1.0.0-1.svn304.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vhba-kernel-2.6.27.4-server-2mnb-1.0.0-1.svn304.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vhba-kernel-desktop586-latest-1.0.0-1.20081106.1.svn304.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vhba-kernel-desktop-latest-1.0.0-1.20081106.1.svn304.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vhba-kernel-server-latest-1.0.0-1.20081106.1.svn304.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"virtualbox-kernel-2.6.27.4-desktop-2mnb-2.0.2-2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"virtualbox-kernel-2.6.27.4-desktop586-2mnb-2.0.2-2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"virtualbox-kernel-2.6.27.4-server-2mnb-2.0.2-2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"virtualbox-kernel-desktop586-latest-2.0.2-1.20081106.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"virtualbox-kernel-desktop-latest-2.0.2-1.20081106.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"virtualbox-kernel-server-latest-2.0.2-1.20081106.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vpnclient-kernel-2.6.27.4-desktop-2mnb-4.8.01.0640-3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vpnclient-kernel-2.6.27.4-desktop586-2mnb-4.8.01.0640-3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vpnclient-kernel-2.6.27.4-server-2mnb-4.8.01.0640-3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vpnclient-kernel-desktop586-latest-4.8.01.0640-1.20081106.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vpnclient-kernel-desktop-latest-4.8.01.0640-1.20081106.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vpnclient-kernel-server-latest-4.8.01.0640-1.20081106.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"kernel-", release:"MDK2009.0") )
{
 set_kb_item(name:"CVE-2008-3528", value:TRUE);
 set_kb_item(name:"CVE-2008-3831", value:TRUE);
 set_kb_item(name:"CVE-2008-4554", value:TRUE);
}
exit(0, "Host is not affected");
