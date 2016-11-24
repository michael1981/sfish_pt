
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27482);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  xen: Security fix for local denial of service problem in alignment fault handler (xen-2156)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch xen-2156");
 script_set_attribute(attribute: "description", value: "This update fixes an issue on x86_64 in which a user-level
application can crash the guest OS when running Xen.

The AC (alignment check) flag in RFLAGS was not being
cleared on entry to the guest kernel, causing unwanted
faults because the kernel runs in ring 3 on Xen.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch xen-2156");
script_end_attributes();

script_summary(english: "Check for the xen-2156 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"xen-3.0.2_09763-0.8", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"xen-devel-3.0.2_09763-0.8", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"xen-doc-html-3.0.2_09763-0.8", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"xen-doc-pdf-3.0.2_09763-0.8", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"xen-doc-ps-3.0.2_09763-0.8", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"xen-libs-3.0.2_09763-0.8", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"xen-libs-32bit-3.0.2_09763-0.8", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"xen-tools-3.0.2_09763-0.8", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"xen-tools-ioemu-3.0.2_09763-0.8", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"yast2-vm-2.13.62-4.2", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
