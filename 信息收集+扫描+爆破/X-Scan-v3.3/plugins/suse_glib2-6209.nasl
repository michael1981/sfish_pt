
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(38181);
 script_version ("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  glib2 security update (glib2-6209)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch glib2-6209");
 script_set_attribute(attribute: "description", value: "Large strings could lead to a heap overflow in the base64
encoding and decoding functions. Attackers could
potentially exploit that to execute arbitrary code
(CVE-2008-4316).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch glib2-6209");
script_end_attributes();

script_cve_id("CVE-2008-4316");
script_summary(english: "Check for the glib2-6209 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"glib2-2.14.1-4.4", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"glib2-32bit-2.14.1-4.4", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"glib2-64bit-2.14.1-4.4", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"glib2-devel-2.14.1-4.4", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"glib2-devel-64bit-2.14.1-4.4", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"glib2-doc-2.14.1-4.4", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"glib2-lang-2.14.1-4.4", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
