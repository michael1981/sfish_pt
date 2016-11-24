
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40302);
 script_version("$Revision: 1.4 $");
 script_name(english: "SuSE 11.1 Security Update:  qemu (2009-03-25)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for qemu");
 script_set_attribute(attribute: "description", value: "qemu update to version 0.10.1 fixes the following security
issues:

CVE-2008-0928: problems with range checks of block devices
CVE-2008-1945: problems with removable media handling
CVE-2008-2382: vnc server DoS CVE-2008-4539: fix a heap
overflow in the cirrus VGA implementation CVE-2008-5714:
off by one error in vnc password handling
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for qemu");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=435135");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=462502");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=461565");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=362956");
script_end_attributes();

 script_cve_id("CVE-2008-0928", "CVE-2008-1945", "CVE-2008-2382", "CVE-2008-4539", "CVE-2008-5714");
script_summary(english: "Check for the qemu package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"qemu-0.10.1-0.1.1", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"qemu-0.10.1-0.1.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");
