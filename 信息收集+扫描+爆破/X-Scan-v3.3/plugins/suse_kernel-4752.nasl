
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29880);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  Kernel Update for SUSE Linux 10.1 (kernel-4752)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch kernel-4752");
 script_set_attribute(attribute: "description", value: "This kernel update fixes the following security problems:

++ CVE-2007-3104: The sysfs_readdir function in the Linux
 kernel 2.6 allows local users to cause a denial of
 service  (kernel OOPS) by dereferencing a null pointer to
 an inode in a dentry.

++ CVE-2007-4997: A 2 byte buffer underflow in the
 ieee80211 stack was fixed, which might be used by
 attackers in the local WLAN reach to crash the machine.

++ CVE-2007-3740: The CIFS filesystem, when Unix extension
 support is enabled, did not honor the umask of a process,
 which allowed local users to gain privileges.

++ CVE-2007-4573: It was possible for local user to become
 root by exploiting a bug in the IA32 system call
 emulation. This problem affects the x86_64 platform only,
 on all distributions.

                  This problem was fixed for regular
kernels, but had not been fixed for the XEN kernels. This
update fixes the problem also for the XEN kernels.

++ CVE-2007-4308: The (1) aac_cfg_open and (2)
 aac_compat_ioctl functions in the SCSI layer ioctl path in
 aacraid did not check permissions for ioctls, which might
 have allowed local users to cause a denial of service or
 gain privileges.

++ CVE-2007-3843: The Linux kernel checked the wrong global
 variable for the CIFS sec mount option, which might allow
 remote attackers to spoof CIFS network traffic that the
 client configured for security signatures, as demonstrated
 by lack of signing despite sec=ntlmv2i in a SetupAndX
 request.

++ CVE-2007-5904: Multiple buffer overflows in CIFS VFS in
 the Linux kernel allowed remote attackers to cause a
 denial of service (crash) and possibly execute arbitrary
 code via long SMB responses that trigger the overflows in
 the SendReceive function.

                  This requires the attacker to mis-present
/ replace a CIFS server the client machine is connected to.

++ CVE-2007-6063: Buffer overflow in the isdn_net_setcfg
 function in isdn_net.c in the Linux kernel allowed local
 users to have an unknown impact via a crafted argument to
 the isdn_ioctl function.

Furthermore, this kernel catches up to the SLE 10 state of
the kernel, with numerous additional fixes.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch kernel-4752");
script_end_attributes();

script_cve_id("CVE-2007-3104", "CVE-2007-4997", "CVE-2007-3740", "CVE-2007-4573", "CVE-2007-4308", "CVE-2007-3843", "CVE-2007-5904", "CVE-2007-6063");
script_summary(english: "Check for the kernel-4752 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"kernel-bigsmp-2.6.16.54-0.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.16.54-0.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.16.54-0.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-iseries64-2.6.16.54-0.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-kdump-2.6.16.54-0.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-ppc64-2.6.16.54-0.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.16.54-0.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.16.54-0.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.16.54-0.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-um-2.6.16.54-0.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.16.54-0.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xenpae-2.6.16.54-0.2.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
