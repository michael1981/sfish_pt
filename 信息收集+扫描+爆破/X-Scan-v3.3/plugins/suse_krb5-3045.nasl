
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27308);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  krb5 security update (krb5-3045)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch krb5-3045");
 script_set_attribute(attribute: "description", value: "A bug in the function krb5_klog_syslog() leads to a buffer
overflow which could be exploited to execute arbitrary code
(CVE-2007-0957).

A double-free bug in the GSS-API library could crash
kadmind. It's potentially also exploitable to execute
arbitrary code (CVE-2007-1216).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch krb5-3045");
script_end_attributes();

script_cve_id("CVE-2007-0957", "CVE-2007-1216");
script_summary(english: "Check for the krb5-3045 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"krb5-1.5.1-23.4", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"krb5-32bit-1.5.1-23.4", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"krb5-64bit-1.5.1-23.4", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"krb5-devel-1.5.1-23.4", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"krb5-devel-32bit-1.5.1-23.4", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"krb5-devel-64bit-1.5.1-23.4", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"krb5-server-1.5.1-23.4", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
