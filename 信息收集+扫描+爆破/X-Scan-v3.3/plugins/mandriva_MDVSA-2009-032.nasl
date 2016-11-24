
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37078);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:032: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:032 (kernel).");
 script_set_attribute(attribute: "description", value: "Some vulnerabilities were discovered and corrected in the Linux
2.6 kernel:
net/atm/svc.c in the ATM subsystem in the Linux kernel 2.6.27.8
and earlier allows local users to cause a denial of service (kernel
infinite loop) by making two calls to svc_listen for the same socket,
and then reading a /proc/net/atm/*vc file, related to corruption of
the vcc table. (CVE-2008-5079)
Linux kernel 2.6.28 allows local users to cause a denial of service
(soft lockup and process loss) via a large number of sendmsg function
calls, which does not block during AF_UNIX garbage collection
and triggers an OOM condition, a different vulnerability than
CVE-2008-5029. (CVE-2008-5300)
Additionaly, wireless and hotkeys support for Asus EEE were fixed,
systems with HDA sound needing MSI support were added to the quirks
list to be autodetected, STAC92HD71Bx and STAC92HD75Bx based HDA
support was enhanced and fixed, support for HDA sound on Acer Aspire
8930 was added, Dell Inspiron Mini 9 HDA sound support was added, CIFS
filesystem should now work with Kerberos, and a few more things. Check
the package changelog for details.
To update your kernel, please follow the directions located at:
http://www.mandriva.com/en/security/kernelupdate
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:032");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-5029", "CVE-2008-5079", "CVE-2008-5300");
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

if ( rpm_check( reference:"alsa_raoppcm-kernel-2.6.27.10-desktop-1mnb-0.5.1-2mdv2008.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"alsa_raoppcm-kernel-2.6.27.10-desktop586-1mnb-0.5.1-2mdv2008.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"alsa_raoppcm-kernel-2.6.27.10-server-1mnb-0.5.1-2mdv2008.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"alsa_raoppcm-kernel-desktop586-latest-0.5.1-1.20090130.2mdv2008.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"alsa_raoppcm-kernel-desktop-latest-0.5.1-1.20090130.2mdv2008.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"alsa_raoppcm-kernel-server-latest-0.5.1-1.20090130.2mdv2008.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"drm-experimental-kernel-2.6.27.10-desktop-1mnb-2.3.0-2.20080912.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"drm-experimental-kernel-2.6.27.10-desktop586-1mnb-2.3.0-2.20080912.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"drm-experimental-kernel-2.6.27.10-server-1mnb-2.3.0-2.20080912.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"drm-experimental-kernel-desktop586-latest-2.3.0-1.20090130.2.20080912.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"drm-experimental-kernel-desktop-latest-2.3.0-1.20090130.2.20080912.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"drm-experimental-kernel-server-latest-2.3.0-1.20090130.2.20080912.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"et131x-kernel-2.6.27.10-desktop-1mnb-1.2.3-7mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"et131x-kernel-2.6.27.10-desktop586-1mnb-1.2.3-7mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"et131x-kernel-2.6.27.10-server-1mnb-1.2.3-7mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"et131x-kernel-desktop586-latest-1.2.3-1.20090130.7mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"et131x-kernel-desktop-latest-1.2.3-1.20090130.7mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"et131x-kernel-server-latest-1.2.3-1.20090130.7mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fcpci-kernel-2.6.27.10-desktop-1mnb-3.11.07-7mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fcpci-kernel-2.6.27.10-desktop586-1mnb-3.11.07-7mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fcpci-kernel-2.6.27.10-server-1mnb-3.11.07-7mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fcpci-kernel-desktop586-latest-3.11.07-1.20090130.7mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fcpci-kernel-desktop-latest-3.11.07-1.20090130.7mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fcpci-kernel-server-latest-3.11.07-1.20090130.7mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fglrx-kernel-2.6.27.10-desktop-1mnb-8.522-3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fglrx-kernel-2.6.27.10-desktop586-1mnb-8.522-3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fglrx-kernel-2.6.27.10-server-1mnb-8.522-3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fglrx-kernel-desktop586-latest-8.522-1.20090130.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fglrx-kernel-desktop-latest-8.522-1.20090130.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fglrx-kernel-server-latest-8.522-1.20090130.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gnbd-kernel-2.6.27.10-desktop-1mnb-2.03.07-2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gnbd-kernel-2.6.27.10-desktop586-1mnb-2.03.07-2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gnbd-kernel-2.6.27.10-server-1mnb-2.03.07-2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gnbd-kernel-desktop586-latest-2.03.07-1.20090130.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gnbd-kernel-desktop-latest-2.03.07-1.20090130.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gnbd-kernel-server-latest-2.03.07-1.20090130.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hcfpcimodem-kernel-2.6.27.10-desktop-1mnb-1.17-1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hcfpcimodem-kernel-2.6.27.10-desktop586-1mnb-1.17-1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hcfpcimodem-kernel-2.6.27.10-server-1mnb-1.17-1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hcfpcimodem-kernel-desktop586-latest-1.17-1.20090130.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hcfpcimodem-kernel-desktop-latest-1.17-1.20090130.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hcfpcimodem-kernel-server-latest-1.17-1.20090130.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hsfmodem-kernel-2.6.27.10-desktop-1mnb-7.68.00.13-1.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hsfmodem-kernel-2.6.27.10-desktop586-1mnb-7.68.00.13-1.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hsfmodem-kernel-2.6.27.10-server-1mnb-7.68.00.13-1.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hsfmodem-kernel-desktop586-latest-7.68.00.13-1.20090130.1.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hsfmodem-kernel-desktop-latest-7.68.00.13-1.20090130.1.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hsfmodem-kernel-server-latest-7.68.00.13-1.20090130.1.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hso-kernel-2.6.27.10-desktop-1mnb-1.2-2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hso-kernel-2.6.27.10-desktop586-1mnb-1.2-2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hso-kernel-2.6.27.10-server-1mnb-1.2-2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hso-kernel-desktop586-latest-1.2-1.20090130.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hso-kernel-desktop-latest-1.2-1.20090130.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hso-kernel-server-latest-1.2-1.20090130.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"iscsitarget-kernel-2.6.27.10-desktop-1mnb-0.4.16-4mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"iscsitarget-kernel-2.6.27.10-desktop586-1mnb-0.4.16-4mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"iscsitarget-kernel-2.6.27.10-server-1mnb-0.4.16-4mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"iscsitarget-kernel-desktop586-latest-0.4.16-1.20090130.4mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"iscsitarget-kernel-desktop-latest-0.4.16-1.20090130.4mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"iscsitarget-kernel-server-latest-0.4.16-1.20090130.4mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.6.27.10-1mnb-1-1mnb2", release:"MDK2009.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-desktop-2.6.27.10-1mnb-1-1mnb2", release:"MDK2009.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-desktop586-2.6.27.10-1mnb-1-1mnb2", release:"MDK2009.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-desktop586-devel-2.6.27.10-1mnb-1-1mnb2", release:"MDK2009.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-desktop586-devel-latest-2.6.27.10-1mnb2", release:"MDK2009.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-desktop586-latest-2.6.27.10-1mnb2", release:"MDK2009.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-desktop-devel-2.6.27.10-1mnb-1-1mnb2", release:"MDK2009.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-desktop-devel-latest-2.6.27.10-1mnb2", release:"MDK2009.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-desktop-latest-2.6.27.10-1mnb2", release:"MDK2009.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.27.10-1mnb2", release:"MDK2009.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-server-2.6.27.10-1mnb-1-1mnb2", release:"MDK2009.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-server-devel-2.6.27.10-1mnb-1-1mnb2", release:"MDK2009.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-server-devel-latest-2.6.27.10-1mnb2", release:"MDK2009.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-server-latest-2.6.27.10-1mnb2", release:"MDK2009.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.27.10-1mnb-1-1mnb2", release:"MDK2009.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-latest-2.6.27.10-1mnb2", release:"MDK2009.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kqemu-kernel-2.6.27.10-desktop-1mnb-1.4.0pre1-0", release:"MDK2009.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kqemu-kernel-2.6.27.10-desktop586-1mnb-1.4.0pre1-0", release:"MDK2009.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kqemu-kernel-2.6.27.10-server-1mnb-1.4.0pre1-0", release:"MDK2009.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kqemu-kernel-desktop586-latest-1.4.0pre1-1.20090130.0", release:"MDK2009.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kqemu-kernel-desktop-latest-1.4.0pre1-1.20090130.0", release:"MDK2009.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kqemu-kernel-server-latest-1.4.0pre1-1.20090130.0", release:"MDK2009.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"lirc-kernel-2.6.27.10-desktop-1mnb-0.8.3-4.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"lirc-kernel-2.6.27.10-desktop586-1mnb-0.8.3-4.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"lirc-kernel-2.6.27.10-server-1mnb-0.8.3-4.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"lirc-kernel-desktop586-latest-0.8.3-1.20090130.4.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"lirc-kernel-desktop-latest-0.8.3-1.20090130.4.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"lirc-kernel-server-latest-0.8.3-1.20090130.4.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"lzma-kernel-2.6.27.10-desktop-1mnb-4.43-24mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"lzma-kernel-2.6.27.10-desktop586-1mnb-4.43-24mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"lzma-kernel-2.6.27.10-server-1mnb-4.43-24mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"lzma-kernel-desktop586-latest-4.43-1.20090130.24mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"lzma-kernel-desktop-latest-4.43-1.20090130.24mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"lzma-kernel-server-latest-4.43-1.20090130.24mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"madwifi-kernel-2.6.27.10-desktop-1mnb-0.9.4-3.r3835mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"madwifi-kernel-2.6.27.10-desktop586-1mnb-0.9.4-3.r3835mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"madwifi-kernel-2.6.27.10-server-1mnb-0.9.4-3.r3835mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"madwifi-kernel-desktop586-latest-0.9.4-1.20090130.3.r3835mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"madwifi-kernel-desktop-latest-0.9.4-1.20090130.3.r3835mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"madwifi-kernel-server-latest-0.9.4-1.20090130.3.r3835mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nvidia173-kernel-2.6.27.10-desktop-1mnb-173.14.12-4mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nvidia173-kernel-2.6.27.10-desktop586-1mnb-173.14.12-4mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nvidia173-kernel-desktop586-latest-173.14.12-1.20090130.4mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nvidia173-kernel-desktop-latest-173.14.12-1.20090130.4mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nvidia71xx-kernel-2.6.27.10-desktop-1mnb-71.86.06-5mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nvidia71xx-kernel-2.6.27.10-desktop586-1mnb-71.86.06-5mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nvidia71xx-kernel-2.6.27.10-server-1mnb-71.86.06-5mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nvidia71xx-kernel-desktop586-latest-71.86.06-1.20090130.5mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nvidia71xx-kernel-desktop-latest-71.86.06-1.20090130.5mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nvidia71xx-kernel-server-latest-71.86.06-1.20090130.5mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nvidia96xx-kernel-2.6.27.10-desktop-1mnb-96.43.07-5mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nvidia96xx-kernel-2.6.27.10-desktop586-1mnb-96.43.07-5mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nvidia96xx-kernel-2.6.27.10-server-1mnb-96.43.07-5mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nvidia96xx-kernel-desktop586-latest-96.43.07-1.20090130.5mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nvidia96xx-kernel-desktop-latest-96.43.07-1.20090130.5mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nvidia96xx-kernel-server-latest-96.43.07-1.20090130.5mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nvidia-current-kernel-2.6.27.10-desktop-1mnb-177.70-2.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nvidia-current-kernel-2.6.27.10-desktop586-1mnb-177.70-2.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nvidia-current-kernel-2.6.27.10-server-1mnb-177.70-2.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nvidia-current-kernel-desktop586-latest-177.70-1.20090130.2.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nvidia-current-kernel-desktop-latest-177.70-1.20090130.2.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nvidia-current-kernel-server-latest-177.70-1.20090130.2.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"omfs-kernel-2.6.27.10-desktop-1mnb-0.8.0-1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"omfs-kernel-2.6.27.10-desktop586-1mnb-0.8.0-1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"omfs-kernel-2.6.27.10-server-1mnb-0.8.0-1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"omfs-kernel-desktop586-latest-0.8.0-1.20090130.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"omfs-kernel-desktop-latest-0.8.0-1.20090130.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"omfs-kernel-server-latest-0.8.0-1.20090130.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"omnibook-kernel-2.6.27.10-desktop-1mnb-20080513-0.274.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"omnibook-kernel-2.6.27.10-desktop586-1mnb-20080513-0.274.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"omnibook-kernel-2.6.27.10-server-1mnb-20080513-0.274.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"omnibook-kernel-desktop586-latest-20080513-1.20090130.0.274.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"omnibook-kernel-desktop-latest-20080513-1.20090130.0.274.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"omnibook-kernel-server-latest-20080513-1.20090130.0.274.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"opencbm-kernel-2.6.27.10-desktop-1mnb-0.4.2a-1mdv2008.1", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"opencbm-kernel-2.6.27.10-desktop586-1mnb-0.4.2a-1mdv2008.1", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"opencbm-kernel-2.6.27.10-server-1mnb-0.4.2a-1mdv2008.1", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"opencbm-kernel-desktop586-latest-0.4.2a-1.20090130.1mdv2008.1", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"opencbm-kernel-desktop-latest-0.4.2a-1.20090130.1mdv2008.1", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"opencbm-kernel-server-latest-0.4.2a-1.20090130.1mdv2008.1", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ov51x-jpeg-kernel-2.6.27.10-desktop-1mnb-1.5.9-2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ov51x-jpeg-kernel-2.6.27.10-desktop586-1mnb-1.5.9-2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ov51x-jpeg-kernel-2.6.27.10-server-1mnb-1.5.9-2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ov51x-jpeg-kernel-desktop586-latest-1.5.9-1.20090130.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ov51x-jpeg-kernel-desktop-latest-1.5.9-1.20090130.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ov51x-jpeg-kernel-server-latest-1.5.9-1.20090130.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"qc-usb-kernel-2.6.27.10-desktop-1mnb-0.6.6-6mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"qc-usb-kernel-2.6.27.10-desktop586-1mnb-0.6.6-6mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"qc-usb-kernel-2.6.27.10-server-1mnb-0.6.6-6mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"qc-usb-kernel-desktop586-latest-0.6.6-1.20090130.6mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"qc-usb-kernel-desktop-latest-0.6.6-1.20090130.6mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"qc-usb-kernel-server-latest-0.6.6-1.20090130.6mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rt2860-kernel-2.6.27.10-desktop-1mnb-1.7.0.0-2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rt2860-kernel-2.6.27.10-desktop586-1mnb-1.7.0.0-2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rt2860-kernel-2.6.27.10-server-1mnb-1.7.0.0-2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rt2860-kernel-desktop586-latest-1.7.0.0-1.20090130.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rt2860-kernel-desktop-latest-1.7.0.0-1.20090130.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rt2860-kernel-server-latest-1.7.0.0-1.20090130.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rt2870-kernel-2.6.27.10-desktop-1mnb-1.3.1.0-2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rt2870-kernel-2.6.27.10-desktop586-1mnb-1.3.1.0-2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rt2870-kernel-2.6.27.10-server-1mnb-1.3.1.0-2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rt2870-kernel-desktop586-latest-1.3.1.0-1.20090130.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rt2870-kernel-desktop-latest-1.3.1.0-1.20090130.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rt2870-kernel-server-latest-1.3.1.0-1.20090130.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rtl8187se-kernel-2.6.27.10-desktop-1mnb-1016.20080716-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rtl8187se-kernel-2.6.27.10-desktop586-1mnb-1016.20080716-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rtl8187se-kernel-2.6.27.10-server-1mnb-1016.20080716-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rtl8187se-kernel-desktop586-latest-1016.20080716-1.20090130.1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rtl8187se-kernel-desktop-latest-1016.20080716-1.20090130.1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rtl8187se-kernel-server-latest-1016.20080716-1.20090130.1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"slmodem-kernel-2.6.27.10-desktop-1mnb-2.9.11-0.20080817.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"slmodem-kernel-2.6.27.10-desktop586-1mnb-2.9.11-0.20080817.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"slmodem-kernel-2.6.27.10-server-1mnb-2.9.11-0.20080817.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"slmodem-kernel-desktop586-latest-2.9.11-1.20090130.0.20080817.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"slmodem-kernel-desktop-latest-2.9.11-1.20090130.0.20080817.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"slmodem-kernel-server-latest-2.9.11-1.20090130.0.20080817.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"squashfs-lzma-kernel-2.6.27.10-desktop-1mnb-3.3-5mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"squashfs-lzma-kernel-2.6.27.10-desktop586-1mnb-3.3-5mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"squashfs-lzma-kernel-2.6.27.10-server-1mnb-3.3-5mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"squashfs-lzma-kernel-desktop586-latest-3.3-1.20090130.5mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"squashfs-lzma-kernel-desktop-latest-3.3-1.20090130.5mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"squashfs-lzma-kernel-server-latest-3.3-1.20090130.5mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tp_smapi-kernel-2.6.27.10-desktop-1mnb-0.37-2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tp_smapi-kernel-2.6.27.10-desktop586-1mnb-0.37-2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tp_smapi-kernel-2.6.27.10-server-1mnb-0.37-2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tp_smapi-kernel-desktop586-latest-0.37-1.20090130.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tp_smapi-kernel-desktop-latest-0.37-1.20090130.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tp_smapi-kernel-server-latest-0.37-1.20090130.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vboxadd-kernel-2.6.27.10-desktop-1mnb-2.0.2-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vboxadd-kernel-2.6.27.10-desktop586-1mnb-2.0.2-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vboxadd-kernel-2.6.27.10-server-1mnb-2.0.2-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vboxadd-kernel-desktop586-latest-2.0.2-1.20090130.2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vboxadd-kernel-desktop-latest-2.0.2-1.20090130.2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vboxadd-kernel-server-latest-2.0.2-1.20090130.2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vboxvfs-kernel-2.6.27.10-desktop-1mnb-2.0.2-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vboxvfs-kernel-2.6.27.10-desktop586-1mnb-2.0.2-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vboxvfs-kernel-2.6.27.10-server-1mnb-2.0.2-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vboxvfs-kernel-desktop586-latest-2.0.2-1.20090130.2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vboxvfs-kernel-desktop-latest-2.0.2-1.20090130.2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vboxvfs-kernel-server-latest-2.0.2-1.20090130.2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vhba-kernel-2.6.27.10-desktop-1mnb-1.0.0-1.svn304.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vhba-kernel-2.6.27.10-desktop586-1mnb-1.0.0-1.svn304.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vhba-kernel-2.6.27.10-server-1mnb-1.0.0-1.svn304.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vhba-kernel-desktop586-latest-1.0.0-1.20090130.1.svn304.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vhba-kernel-desktop-latest-1.0.0-1.20090130.1.svn304.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vhba-kernel-server-latest-1.0.0-1.20090130.1.svn304.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"virtualbox-kernel-2.6.27.10-desktop-1mnb-2.0.2-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"virtualbox-kernel-2.6.27.10-desktop586-1mnb-2.0.2-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"virtualbox-kernel-2.6.27.10-server-1mnb-2.0.2-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"virtualbox-kernel-desktop586-latest-2.0.2-1.20090130.2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"virtualbox-kernel-desktop-latest-2.0.2-1.20090130.2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"virtualbox-kernel-server-latest-2.0.2-1.20090130.2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vpnclient-kernel-2.6.27.10-desktop-1mnb-4.8.01.0640-3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vpnclient-kernel-2.6.27.10-desktop586-1mnb-4.8.01.0640-3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vpnclient-kernel-2.6.27.10-server-1mnb-4.8.01.0640-3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vpnclient-kernel-desktop586-latest-4.8.01.0640-1.20090130.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vpnclient-kernel-desktop-latest-4.8.01.0640-1.20090130.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vpnclient-kernel-server-latest-4.8.01.0640-1.20090130.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"kernel-", release:"MDK2009.0") )
{
 set_kb_item(name:"CVE-2008-5029", value:TRUE);
 set_kb_item(name:"CVE-2008-5079", value:TRUE);
 set_kb_item(name:"CVE-2008-5300", value:TRUE);
}
exit(0, "Host is not affected");
