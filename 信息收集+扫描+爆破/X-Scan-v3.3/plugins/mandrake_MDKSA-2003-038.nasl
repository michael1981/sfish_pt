
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14022);
 script_version ("$Revision: 1.7 $");
 script_name(english: "MDKSA-2003:038: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:038 (kernel).");
 script_set_attribute(attribute: "description", value: "A bug in the kernel module loader code could allow a local user to gain
root privileges. This is done by a local user using ptrace and
attaching to a modprobe process that is spawned if the user triggers
the loading of a kernel module.
A temporary workaround can be used to defend against this flaw. It is
possible to temporarily disable the kmod kernel module loading
subsystem in the kernel after all of the required kernel modules have
been loaded. Be sure that you do not need to load additional kernel
modules after implementing this workaround. To use it, as root execute:
echo /no/such/file >/proc/sys/kernel/modprobe
To automate this, you may wish to add it as the last line of the
/etc/rc.d/rc.local file. You can revert this change by replacing the
content '/sbin/modprobe' in the /proc/sys/kernel/modprobe file. The
root user can still manually load kernel modules with this workaround
in place.
This update applies a patch to correct the problem. All users should
upgrade. Please note that the Mandrake Linux 9.1 kernel already has
this patch, and an updated kernel for Mandrake Linux 8.2 will be
available shortly.
For instructions on how to upgrade your kernel in Mandrake Linux,
please refer to:
http://www.mandrakesecure.net/en/kernelupdate.php
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:038");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-0127");
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

if ( rpm_check( reference:"kernel-2.4.19.32mdk-1-1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.19.32mdk-1-1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.4.19.32mdk-1-1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-secure-2.4.19.32mdk-1-1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.19.32mdk-1-1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.19-32mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"kernel-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2003-0127", value:TRUE);
}
exit(0, "Host is not affected");
