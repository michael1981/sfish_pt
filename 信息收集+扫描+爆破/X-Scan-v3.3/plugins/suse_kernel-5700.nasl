
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(34457);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  undocumented patch for 3837c2df513f0088f0fdd19fc0db5adc (kernel-5700)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch kernel-5700");
 script_set_attribute(attribute: "description", value: "The openSUSE 10.3 kernel was update to 2.6.22.19. This
includes bugs and security fixes.

CVE-2008-4576: Fixed a crash in SCTP INIT-ACK, on mismatch
between SCTP AUTH availability. This might be exploited
remotely for a denial of service (crash) attack.

CVE-2008-3528: The ext[234] filesystem code fails to
properly handle corrupted data structures. With a mounted
filesystem image or partition that have corrupted
dir->i_size and dir->i_blocks, a user performing either a
read or write operation on the mounted image or partition
can lead to a possible denial of service by spamming the
logfile.

CVE-2007-6716: fs/direct-io.c in the dio subsystem in the
Linux kernel did not properly zero out the dio struct,
which allows local users to cause a denial of service
(OOPS), as demonstrated by a certain fio test.

CVE-2008-3525: Added missing capability checks in
sbni_ioctl().

CVE-2008-3272: Fixed range checking in the snd_seq OSS
ioctl, which could be used to leak information from the
kernel.

CVE-2008-3276: An integer overflow flaw was found in the
Linux kernel dccp_setsockopt_change() function. An attacker
may leverage this vulnerability to trigger a kernel panic
on a victim's machine remotely.

CVE-2008-1673: Added range checking in ASN.1 handling for
the CIFS and SNMP NAT netfilter modules.

CVE-2008-2826: A integer overflow in SCTP was fixed, which
might have been used by remote attackers to crash the
machine or potentially execute code.

CVE-2008-2812: Various NULL ptr checks have been added to
tty op functions, which might have been used by local
attackers to execute code. We think that this affects only
devices openable by root, so the impact is limited.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch kernel-5700");
script_end_attributes();

script_cve_id("CVE-2008-4576", "CVE-2008-3528", "CVE-2007-6716", "CVE-2008-3525", "CVE-2008-3272", "CVE-2008-3276", "CVE-2008-1673", "CVE-2008-2826", "CVE-2008-2812");
script_summary(english: "Check for the kernel-5700 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"kernel-bigsmp-2.6.22.19-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.22.19-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.22.19-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-kdump-2.6.22.19-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-ppc64-2.6.22.19-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.22.19-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.22.19-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.22.19-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xenpae-2.6.22.19-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
