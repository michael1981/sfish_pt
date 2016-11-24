
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(34289);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  bluez security update (bluez-audio-5441)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch bluez-audio-5441");
 script_set_attribute(attribute: "description", value: "Missing length checks in bluez-libs could cause a buffer
overflow in Bluetooth applications. Malicious bluetooth
devices could potentially exploit that to execute arbitrary
code (CVE-2008-2374).

Note: The source code of each application that uses
vulnerable functions of bluez-libs needs to be adapted to
actually fix the problem.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch bluez-audio-5441");
script_end_attributes();

script_cve_id("CVE-2008-2374");
script_summary(english: "Check for the bluez-audio-5441 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"bluez-cups-3.18-13.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"bluez-libs-3.18-5.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"bluez-test-3.18-13.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"bluez-utils-3.18-13.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
