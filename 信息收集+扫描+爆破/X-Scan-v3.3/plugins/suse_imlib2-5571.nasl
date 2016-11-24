
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(34193);
 script_version ("$Revision: 1.3 $");
 script_name(english: "SuSE Security Update:  imlib2: Fixed an overflow in the XPM and a crash in the PNM loader (imlib2-5571)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch imlib2-5571");
 script_set_attribute(attribute: "description", value: "This update fixes two security problems in imlib2.

Specially crafted xpm files could trigger a stack based
buffer overflow in imlib2 which could potentially be
exploited to execute arbitrary code (CVE-2008-2426).

A crash in PNM handling due to a NULL pointer dereference
was fixed.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch imlib2-5571");
script_end_attributes();

script_cve_id("CVE-2008-2426");
script_summary(english: "Check for the imlib2-5571 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"imlib2-1.3.0-66.3", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"imlib2-devel-1.3.0-66.3", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"imlib2-filters-1.3.0-66.3", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"imlib2-loaders-1.3.0-66.3", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
