
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29596);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  Security update for Xen (xen-2155)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch xen-2155");
 script_set_attribute(attribute: "description", value: "This update includes both bug fixes and security fixes for
Xen.

A summary of the fixes appears below: 151105 - Fix various
'leaks' of loopback devices w/ domUloader 162865 - Re-send
all page tables when migrating to avoid oops 167145 - Add
status messages during file backed disk creation 176369 -
YaST2-VM incorrectly reports 'Not enough free memory' if
not on xen 176449 - Backport credit scheduler, for better
performance 176717 - [XEN-HVM]Failed to install win2k hvm
guest 184175 - System rebooted during Virtual Machine
(guest OS) installation 184727 - Error starting VM from
YaST with maximum memory size (partial fix) 184727 - fix
calculation of largest memory size of VM 185557 - update
xendomains to wait for shutdown to complete 185557 - 'xm
shutdown -w' must wait for loopback devices to be destroyed
186930 - Logical volumes (LVM) are not displayed when
adding block device 189765 - using an LV as VM block device
gives bogus warning 189815 - Increase balloon timeout
value, for large memory machines 190170 - Do not open
migration port by default 190869 - Default to non-sync
loopback; give choice to user per-disk 191627 - Fix startup
errors in disk created by mk-xen-rescue-img 191853 - Fix
overflows in lomount, for virtual disks > 2 GB 192150 - Xen
issue with privileged instruction 192308 - disable
alignment checks in kernel mode (fixes eDir/NICI) 193854 -
Add arch-invarient qemu-dm link, so config file is portable
193854 - lib vs lib64 is hard-coded into VM definition file
194389 - YaST2 xen Module Bug in X Detection 196169 - Make
domUloader honor the dry-run flag 197777 - do not default
to 'bridge=xenbr0' in the VM config file 201349 -
xendomains did not actually save domains 203731 - Allow
VM's RAM to be enlarged after starting VM (fix maxmem
setting) 204153 - default to using vif0/xenbr0 if vifnum is
not set or no default route 206312 - Fix TEST_UNIT_READY to
work with ISO images; fixes Windows BSOD. 209743 - Do not
delay interrupt injection if the guest IF_FLAG disallows
intr xxxxxx - changeset 9763: grant table fix xxxxxx - do
not expose MCE/MCA bits in CPUID on SVM xxxxxx - quiet
debug messages in SVM xxxxxx - update block-nbd so that it
works again
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Install the security patch xen-2155");
script_end_attributes();

script_summary(english: "Check for the xen-2155 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"xen-3.0.2_09763-0.8", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"xen-devel-3.0.2_09763-0.8", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"xen-doc-html-3.0.2_09763-0.8", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"xen-doc-pdf-3.0.2_09763-0.8", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"xen-doc-ps-3.0.2_09763-0.8", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"xen-libs-3.0.2_09763-0.8", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"xen-tools-3.0.2_09763-0.8", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"xen-tools-ioemu-3.0.2_09763-0.8", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"yast2-vm-2.13.62-4.2", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
