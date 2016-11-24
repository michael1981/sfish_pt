
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41416);
 script_version("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  kvm (2009-08-06)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for kvm");
 script_set_attribute(attribute: "description", value: "The KVM technology available as Technical Preview in SUSE
Linux Enterprise has been updated to version 0.10.5.

While a minor security issue was fixed, this mainly is a
huge version update.

Changelog:
  - 'info chardev' monitor command
  - automatic port allocation for vnc and similar
  - improved cdrom media change handling
  - scsi improvements
  - e1000 vlan offload
  - fix interrupt loss when injecting an nmi
  - SPT optimizations
  - x86 emulator improvements
  - fix amd->intel migration
  - enable virtio zero-copy (Mark McLoughlin)
  - uuid support
  - hpet support
  - '-drive serial=...' option
  - improved tsc handling (Marcelo Tosatti)
  - guest S3 sleep (Gleb Natapov)
  - '-no-kvm-pit-reinjection' option to improve timing on
    RHEL 3 era guests (Marcelo Tosatti)
  - fix xen-on-kvm
  - enable ac97 audio by default
  - add virtio-console device
  - fix rtc time drift on Windows (-rtc-td-hack option)
  - vnc improvements
  - fix kvmclock on hosts with unstable tsc (Gerd Hoffman)
  - fix cygwin on Windows x64 
- enable nested paging again

And the KVM kernel module was upgraded to 2.6.30.1:
  - check for CR3 set (bnc#517671, CVE-2009-2287)
  - fix cpuid
  - fix guest reboot failures
  - fix interrupt loss when injecting an nmi
  - SPT optimizations
  - x86 emulator improvements
  - fix amd->intel migration
  - improved tsc handling (Marcelo Tosatti)
  - vnc improvements
  - fix kvmclock on hosts with unstable tsc (Gerd Hoffman)
  - fix cygwin on Windows x64
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for kvm");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=517671");
script_end_attributes();

 script_cve_id("CVE-2009-2287");
script_summary(english: "Check for the kvm package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"kvm-78.0.10.5-0.2.1", release:"SLES11", cpu:"i586") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kvm-kmp-default-78.2.6.30.1_2.6.27.25_0.1-0.2.1", release:"SLES11", cpu:"i586") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kvm-kmp-pae-78.2.6.30.1_2.6.27.25_0.1-0.2.1", release:"SLES11", cpu:"i586") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kvm-78.0.10.5-0.2.1", release:"SLED11", cpu:"i586") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kvm-kmp-default-78.2.6.30.1_2.6.27.25_0.1-0.2.1", release:"SLED11", cpu:"i586") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kvm-kmp-pae-78.2.6.30.1_2.6.27.25_0.1-0.2.1", release:"SLED11", cpu:"i586") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
