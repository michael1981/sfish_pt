
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35005);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  imlib2: Fixed heap overflow in XPM loader (imlib2-5804)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch imlib2-5804");
 script_set_attribute(attribute: "description", value: "A security problem was fixed in imlib2 where loading a
specific XPM file could corrupt memory. (CVE-2008-5187)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch imlib2-5804");
script_end_attributes();

script_cve_id("CVE-2008-5187");
script_summary(english: "Check for the imlib2-5804 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"imlib2-1.3.0-66.5", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"imlib2-devel-1.3.0-66.5", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"imlib2-filters-1.3.0-66.5", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"imlib2-loaders-1.3.0-66.5", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
