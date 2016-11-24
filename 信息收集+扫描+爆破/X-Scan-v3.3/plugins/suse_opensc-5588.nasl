
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(34262);
 script_version ("$Revision: 1.8 $");
 script_name(english: "SuSE Security Update:  Security update for opensc, opensc-devel (opensc-5588)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch opensc-5588");
 script_set_attribute(attribute: "description", value: "This update fixes a security issues with opensc that
occured when initializing blank smart cards with Siemens
CardOS M4. After the initialization anyone could set the
PIN of the smart card without authorization (CVE-2008-2235).

NOTE: Already initialized cards are still vulnerable after
this update. Please use the command-line tool pkcs15-tool
with option
--test-update and --update when necessary.

Please find more information at
http://www.opensc-project.org/security.html

This is the second attempt to fix this problem. The
previous update was unforunately incomplete.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:C/A:N");
script_set_attribute(attribute: "solution", value: "Install the security patch opensc-5588");
script_end_attributes();

script_cve_id("CVE-2008-2235");
script_summary(english: "Check for the opensc-5588 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"opensc-0.9.6-17.9", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"opensc-devel-0.9.6-17.9", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"slesp1-opensc-5588-patch-message-2-5588-1", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"opensc-0.9.6-17.9", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"sledp1-opensc-5588-patch-message-2-5588-1", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
