
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37772);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2008:105: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:105 (kernel).");
 script_set_attribute(attribute: "description", value: "The CIFS filesystem in the Linux kernel before 2.6.22, when Unix
extension support is enabled, does not honor the umask of a process,
which allows local users to gain privileges. (CVE-2007-3740)
The drm/i915 component in the Linux kernel before 2.6.22.2, when
used with i965G and later chipsets, allows local users with access
to an X11 session and Direct Rendering Manager (DRM) to write
to arbitrary memory locations and gain privileges via a crafted
batchbuffer. (CVE-2007-3851)
The (1) hugetlb_vmtruncate_list and (2) hugetlb_vmtruncate functions
in fs/hugetlbfs/inode.c in the Linux kernel before 2.6.19-rc4 perform
certain prio_tree calculations using HPAGE_SIZE instead of PAGE_SIZE
units, which allows local users to cause a denial of service (panic)
via unspecified vectors. (CVE-2007-4133)
The IA32 system call emulation functionality in Linux kernel 2.4.x
and 2.6.x before 2.6.22.7, when running on the x86_64 architecture,
does not zero extend the eax register after the 32bit entry path to
ptrace is used, which might allow local users to gain privileges by
triggering an out-of-bounds access to the system call table using
the %RAX register. This vulnerability is now being fixed in the Xen
kernel too. (CVE-2007-4573)
Integer underflow in the ieee80211_rx function in
net/ieee80211/ieee80211_rx.c in the Linux kernel 2.6.x before
2.6.23 allows remote attackers to cause a denial of service (crash)
via a crafted SKB length value in a runt IEEE 802.11 frame when
the IEEE80211_STYPE_QOS_DATA flag is set, aka an off-by-two
error. (CVE-2007-4997)
The disconnect method in the Philips USB Webcam (pwc) driver in Linux
kernel 2.6.x before 2.6.22.6 relies on user space to close the device,
which allows user-assisted local attackers to cause a denial of service
(USB subsystem hang and CPU consumption in khubd) by not closing the
device after the disconnect is invoked. NOTE: this rarely crosses
privilege boundaries, unless the attacker can convince the victim to
unplug the affected device. (CVE-2007-5093)
A race condition in the directory notification subsystem (dnotify)
in Linux kernel 2.6.x before 2.6.24.6, and 2.6.25 before 2.6.25.1,
allows local users to cause a denial of service (OOPS) and possibly
gain privileges via unspecified vectors. (CVE-2008-1375)
The Linux kernel before 2.6.25.2 does not apply a certain protection
mechanism for fcntl functionality, which allows local users to (1)
execute code in parallel or (2) exploit a race condition to obtain
re-ordered access to the descriptor table. (CVE-2008-1669)
To update your kernel, please follow the directions located at:
http://www.mandriva.com/en/security/kernelupdate
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:105");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2007-3740", "CVE-2007-3851", "CVE-2007-4133", "CVE-2007-4573", "CVE-2007-4997", "CVE-2007-5093", "CVE-2008-1375", "CVE-2008-1669");
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

if ( rpm_check( reference:"kernel-2.6.17.18mdv-1-1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.17.18mdv-1-1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-latest-2.6.17-18mdv", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.6.17.18mdv-1-1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-latest-2.6.17-18mdv", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-latest-2.6.17-18mdv", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-legacy-2.6.17.18mdv-1-1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-legacy-latest-2.6.17-18mdv", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.17.18mdv-1-1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-latest-2.6.17-18mdv", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-stripped-2.6.17.18mdv-1-1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-stripped-latest-2.6.17-18mdv", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen0-2.6.17.18mdv-1-1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen0-latest-2.6.17-18mdv", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-2.6.17.18mdv-1-1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-latest-2.6.17-18mdv", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"kernel-", release:"MDK2007.1") )
{
 set_kb_item(name:"CVE-2007-3740", value:TRUE);
 set_kb_item(name:"CVE-2007-3851", value:TRUE);
 set_kb_item(name:"CVE-2007-4133", value:TRUE);
 set_kb_item(name:"CVE-2007-4573", value:TRUE);
 set_kb_item(name:"CVE-2007-4997", value:TRUE);
 set_kb_item(name:"CVE-2007-5093", value:TRUE);
 set_kb_item(name:"CVE-2008-1375", value:TRUE);
 set_kb_item(name:"CVE-2008-1669", value:TRUE);
}
exit(0, "Host is not affected");
