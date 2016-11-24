
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(34073);
 script_version ("$Revision: 1.3 $");
 script_name(english: "SuSE Security Update:  opensc: security issue with Siemens CardOS M4 (libopensc2-5494)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch libopensc2-5494");
 script_set_attribute(attribute: "description", value: "This update fixes a security issues with opensc that occurs
during initializing blank smart cards with Siemens CardOS
M4. It allows to set the PIN of the smart card without
authorization.  (CVE-2008-2235)

NOTE: Already initialized cards are still vulnerable after
this update. Please use the command-line tool pkcs15-tool
with option --test-update and --update when necessary.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:C/A:N");
script_set_attribute(attribute: "solution", value: "Install the security patch libopensc2-5494");
script_end_attributes();

script_cve_id("CVE-2008-2235");
script_summary(english: "Check for the libopensc2-5494 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"libopensc2-0.11.3-21.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libopensc2-32bit-0.11.3-21.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libopensc2-64bit-0.11.3-21.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"opensc-0.11.3-21.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"opensc-32bit-0.11.3-21.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"opensc-64bit-0.11.3-21.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"opensc-devel-0.11.3-21.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
