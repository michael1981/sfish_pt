
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40009);
 script_version("$Revision: 1.3 $");
 script_name(english: "SuSE 11.0 Security Update:  kernel (2008-08-22)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for kernel");
 script_set_attribute(attribute: "description", value: "The openSUSE 11.0 kernel was updated to 2.6.25.16.

It fixes various stability bugs and also security bugs.

CVE-2008-1673: Fixed the range checking in the ASN.1
decoder in NAT for SNMP and CIFS, which could have been
used by a remote attacker to crash the machine.

CVE-2008-3276: An integer overflow flaw was found in the
Linux kernel dccp_setsockopt_change() function. An attacker
may leverage this vulnerability to trigger a kernel panic
on a victim's machine remotely.

CVE-2008-3272: The snd_seq_oss_synth_make_info function in
sound/core/seq/oss/seq_oss_synth.c in the sound subsystem
does not verify that the device number is within the range
defined by max_synthdev before returning certain data to
the caller, which allows local users to obtain sensitive
information.

CVE-2008-3275: The (1) real_lookup and (2) __lookup_hash
functions in fs/namei.c in the vfs implementation do not
prevent creation of a child dentry for a deleted (aka
S_DEAD) directory, which allows local users to cause a
denial of service ('overflow' of the UBIFS orphan area) via
a series of attempted file creations within deleted
directories.

Also lots of bugs were fixed.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for kernel");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=400874");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=216857");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=404892");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=400815");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=408734");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=394667");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=407689");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=417505");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=415607");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=412823");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=415690");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=406637");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=374099");
script_end_attributes();

 script_cve_id("CVE-2008-1673", "CVE-2008-3272", "CVE-2008-3275", "CVE-2008-3276");
script_summary(english: "Check for the kernel package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"kernel-debug-2.6.25.16-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.25.16-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.25.16-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.25.16-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-docs-2.6.25.16-0.1", release:"SUSE11.0", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-pae-2.6.25.16-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-rt-2.6.25.16-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-rt-2.6.25.16-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-rt_debug-2.6.25.16-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.25.16-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.25.16-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.25.16-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.25.16-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-vanilla-2.6.25.16-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-vanilla-2.6.25.16-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.25.16-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.25.16-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");
