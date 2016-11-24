
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24582);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2006:197: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2006:197 (kernel).");
 script_set_attribute(attribute: "description", value: "Some vulnerabilities were discovered and corrected in the Linux 2.6
kernel:
Bugs in the netfilter for IPv6 code, as reported by Mark Dowd, were
fixed (CVE-2006-4572).
The ATM subsystem of the Linux kernel could allow a remote attacker to
cause a Denial of Service (panic) via unknown vectors that cause the
ATM subsystem to access the memory of socket buffers after they are
freed (CVE-2006-4997).
The provided packages are patched to fix these vulnerabilities. All
users are encouraged to upgrade to these updated kernels immediately
and reboot to effect the fixes.
In addition to these security fixes, other fixes have been included
such as:
- updated to 2.6.17.14 - fix wrong error handling in pccard_store_cis -
add NX mask for PTE entry on x86_64 - fix snd-hda-intel OOPS -
backported support r8169-related (r8168/r8169SC) network chipsets -
explicitly initialize some members of the drm_driver structure,
otherwise NULL init will have bad side effects (mach64) - support for
building a nosrc.rpm package - fixed unplug/eject on pcmcia cards with
r8169 chipsets - fix libata resource conflicts - fix xenU crash and
re-enable domU boot logs - fix refcount error triggered by software
using /proc/[pid]/auxv
To update your kernel, please follow the directions located at:
http://www.mandriva.com/en/security/kernelupdate
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:197");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2006-4572", "CVE-2006-4997");
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

if ( rpm_check( reference:"kernel-2.6.17.6mdv-1-1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.6.17.6mdv-1-1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-legacy-2.6.17.6mdv-1-1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.17.6mdv-1-1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-stripped-2.6.17.6mdv-1-1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen0-2.6.17.6mdv-1-1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-2.6.17.6mdv-1-1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"kernel-", release:"MDK2007.0") )
{
 set_kb_item(name:"CVE-2006-4572", value:TRUE);
 set_kb_item(name:"CVE-2006-4997", value:TRUE);
}
exit(0, "Host is not affected");
