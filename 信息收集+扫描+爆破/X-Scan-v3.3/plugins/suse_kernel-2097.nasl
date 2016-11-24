
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
 script_id(29485);
 script_version ("$Revision: 1.7 $");
 script_name(english: "SuSE Security Update:  Security update for Linux kernel (i386) (kernel-2097)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch kernel-2097");
 script_set_attribute(attribute: "description", value: "This kernel update fixes the following security problems:

- CVE-2006-3745: A double userspace copy in a SCTP ioctl
  allows local attackers to overflow a buffer in the
  kernel, potentially allowing code execution and privilege
  escalation. [#199441]

- CVE-2006-4093: Local attackers were able to crash PowerPC
  systems with PPC970 processor using a not correctly
  disabled privileged instruction ('attn'). [#197810]

- CVE-2006-3468: Remote attackers able to access an NFS of
  a ext2 or ext3 filesystem can cause a denial of service
  (file system panic) via a crafted UDP packet with a V2
  lookup procedure that specifies a bad file handle (inode
  number), which triggers an error and causes an exported
  directory to be remounted read-only. [#192988]


and the following non security bugs:

- XEN patches/fixes:
  +  kunmap_atomic() must zap the PTE to avoid dangling
references.
- Fix oops on io scheduler unload on a process without ioc
  (backport)
- OCFS2 updated to to version 1.2.3. 

- update patches.arch/ppc-update_gtod-race.patch: restrict
  to  64bit only because it leads to deadlocks on ppc32
  [#202146]
- Fix MCA recovery in context switch path  [#199472]
- fix gettimeofday vs. update_gtod race  [#197699]
- LKCD: dump all slab pages.  [#196330]
- Make idle io be lowest priority best-effort  [#195387]
- Fix dropping of wrong cic.  [#195387]
- Fix stale file handle problem with subtree_checking.
  [#195040]
- Remove Altix PROM bit that can race on MCAs.  [#193296]
- Prevent silent data corruption caused by XPC.  [#193132]
- Fix race condition during COW  [#192259]
- sched: fix group power for allnodes_domains  [#191929]
- Allow dma_alloc_coherent() to work for regions up to
  2MB.  [#191615]
- fix ABBA deadlock between cpuset callback_sem and hotplug
  cpucontrol mutex  [#191582]
- Check for existing sysfs directory prior to creating one
  [#191360]
- Fix possible NFS panic in readdir.  [#189951]
- MPT driver: Fix oops on module loading   [#189534]
- SUNRPC: Ensure that rpc_mkpipe returns a refcounted
  dentry  [#183013]
- Pass file mode on DMAPI remove events  [#182691]
- MPT driver: Fix oops during error recovery  [#177919]
- flush icache on POWER4 cpus to fix itrace crash  [#171699]
- KPROBES: Fix system panic if user doing copy_from_user in
  the probe handlers  [#171483]
- patches.xen/xen-balloon-max-target: Expose limit domain
  can be ballooned up to  [#152667]
- Avoid possible soft-lockup, particularly related to md
  [#152099]
- reiserfs: fix transaction overflowing  [#145070]


Fixes for S/390:

- IBM Patchcluster 6
    - Problem-ID:  25393 - xpram: module parameter parsing.
    - Problem-ID:  23720 - zfcp: failed paths remain
unavailable
    - Problem-ID:  23989 - zfcp: ERP 'deadlock' when
registering a scsi device or remote port (partII)
    - Problem-ID:  24645 - qeth: qethconf not adding ipa
entries
    - Problem-ID:  25507 - cio: 5 min timeout after setting
chpid offline.
    - Problem-ID:  25511 - cio: Fix some path grouping and
path verification related problems.

- IBM Patchcluster 7
    - Problem-ID:  25564 - qeth: race during setup of qeth
device
    - Problem-ID:  25799 - iucv: multiple interfaces with
same peer established
    - Problem-ID:  25801 - cio: permanent subchannel busy
conditions may cause I/O stall
    - Problem-ID:  23575 - cio: module containing ccwgroup
driver cannot be unloaded.
    - Problem-ID:  25802 - cio: Disallow ccwgroup devices
containing non-unique ccw devices.
    - Problem-ID:  26016 - qeth: race when reboot and
recovery run concurrently
    - Problem-ID:  26068 - qeth: kernel panic under heavy
UDP workload
    - Problem-ID:  26103 - cio: I/O stall due to lost
interupt after CHPID vary off/on cycle
    - Problem-ID:  26014 - qeth: stack trace with msg
'inconsistent lock state'
    - Problem-ID:  26118 - dasd: kernel BUG when setting a
DASD device offline. 
    - Problem-ID:  19628 - zfcp: do adapter reopen on
do_QDIO error
    - Problem-ID:  26144 - qeth: Setrouting for ipv6
invalid on hipersockets.
    - Problem-ID:  23427, 24855 - cio: Inconsistent values
in channel measurement facility.
    - Problem-ID:  24511 - dasd: Cleanup queue fails during
offline processing.

  For further describtion of the named Problem-IDs, please
look to
http://www-128.ibm.com/developerworks/linux/linux390/april20
04_recommended.html

In the former Kernel the HZ_TIMER was switched on by
default. This is now switched off. (see cat
/proc/sys/kernel/hz_timer on the system)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch kernel-2097");
script_end_attributes();

script_cve_id("CVE-2006-3468", "CVE-2006-3745", "CVE-2006-4093");
script_summary(english: "Check for the kernel-2097 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"kernel-bigsmp-2.6.16.21-0.25", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.16.21-0.25", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.16.21-0.25", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.16.21-0.25", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.16.21-0.25", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.16.21-0.25", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.16.21-0.25", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xenpae-2.6.16.21-0.25", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-bigsmp-2.6.16.21-0.25", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.16.21-0.25", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.16.21-0.25", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.16.21-0.25", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.16.21-0.25", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
