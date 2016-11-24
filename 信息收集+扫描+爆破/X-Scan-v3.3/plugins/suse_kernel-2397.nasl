
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if (NASL_LEVEL < 3000 ) exit(0);

if(description)
{
 script_id(27291);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  Kernel Update for SUSE Linux 10.1 (kernel-2397)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch kernel-2397");
 script_set_attribute(attribute: "description", value: "This kernel update fixes the following security problems:
- CVE-2006-4145: A bug within the UDF filesystem that
  caused machine
 hangs when truncating files on the
  filesystem was
 fixed. [#186226]


- -              A potential crash when receiving IPX
  packets
 was fixed. This problem is thought not to be
  exploitable. [#197809]

- CVE-2006-4623: A problem in DVB packet handling could be
  used
 to crash the machine when receiving DVB net
  packages
 is active.  [#201429]


- CVE-2006-3741: A struct file leak was fixed in the
  perfmon(2) system
 call on the Itanium architecture.
  [#202269]


- CVE-2006-4538: A malformed ELF image can be used on the
  Itanium
 architecture to trigger a kernel crash (denial
  of
 service) when a local attacker can supply it to be
  started. [#203822]


- CVE-2006-4997: A problem in the ATM protocol handling
  clip_mkip function
 could be used by remote attackers to
  potentially crash
 the machine. [#205383]

CVE-2006-5757/
- CVE-2006-6060: A problem in the grow_buffers function
  could be
 used to crash or hang the machine using a
  corrupted
 filesystem. This affects filesystem types
  ISO9660 and
 NTFS. [#205384]

- CVE-2006-5173: On the i386 architecture the ELFAGS
  content was not
 correctly saved, which could be used by
  local attackers
 to crash other programs using the AC and
  NT flag or to
 escalate privileges by waiting for iopl
  privileges to 
 be leaked.  [#209386]

- CVE-2006-5174: On the S/390 architecture copy_from_user()
  could be
 used by local attackers to read kernel memory.
  [#209880]

- CVE-2006-5619: A problem in IPv6 flowlabel handling can
  be used by 
 local attackers to hang the machine.
  [#216590]

- CVE-2006-5648: On the PowerPC architecture a syscall has
  been wired
 without the proper futex implementation that
  can be
 exploited by a local attacker to hang the
  machine.
 [#217295]


- CVE-2006-5649: On the PowerPC architecture the proper
  futex
 implementation was missing a fix for alignment
  check
 which could be used by a local attacker to crash
  the
 machine. [#217295]

- CVE-2006-5823: A problem in cramfs could be used to crash
  the machine
 during mounting a crafted cramfs image. This
  requires
 an attacker to supply such a crafted image and
  have a
 user mount it. [#218237]

- CVE-2006-6053: A problem in the ext3 filesystem could be
  used by
 attackers able to supply a crafted ext3 image to
  cause
 a denial of service or further data corruption if
  a
 user mounts this image. [#220288]

- CVE-2006-6056: Missing return code checking in the HFS
  could be used
 to crash machine when a user complicit
  attacker is able
 to supply a specially crafted HFS
  image.
 [#221230]

- CVE-2006-4572: Multiple unspecified vulnerabilities in
  netfilter for
 IPv6 code allow remote attackers to bypass
  intended 
 restrictions via fragmentation attack vectors,
  aka 
 (1) 'ip6_tables protocol bypass bug' and
 (2)
  'ip6_tables extension header bypass bug'.  [#221313]

- CVE-2006-5751: An integer overflow in the networking
  bridge ioctl
 starting with Kernel 2.6.7 could be used by
  local 
 attackers to overflow kernel memory buffers and
  potentially escalate privileges  [#222656]

Additionaly this kernel catches up to the SLE 10 state of
the kernel,
 with massive additional fixes.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch kernel-2397");
script_end_attributes();

script_cve_id("CVE-2006-4145", "CVE-2006-4623", "CVE-2006-3741", "CVE-2006-4538", "CVE-2006-4997", "CVE-2006-5757", "CVE-2006-6060", "CVE-2006-5173", "CVE-2006-5174", "CVE-2006-5619", "CVE-2006-5648", "CVE-2006-5649", "CVE-2006-5823", "CVE-2006-6053", "CVE-2006-6056", "CVE-2006-4572", "CVE-2006-5751");
script_summary(english: "Check for the kernel-2397 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"kernel-bigsmp-2.6.16.27-0.6", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.16.27-0.6", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.16.27-0.6", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-iseries64-2.6.16.27-0.6", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-kdump-2.6.16.27-0.6", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-ppc64-2.6.16.27-0.6", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.16.27-0.6", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.16.27-0.6", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.16.27-0.6", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-um-2.6.16.27-0.6", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.16.27-0.6", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xenpae-2.6.16.27-0.6", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kexec-tools-1.101-32.20", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mkinitrd-1.2-106.25", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"multipath-tools-0.4.6-25.14", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"open-iscsi-0.5.545-9.16", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"udev-085-30.16", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-2397-patch-message-2-2397-1", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
