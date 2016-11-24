
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(36122);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  krb5: security update (krb5-6139)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch krb5-6139");
 script_set_attribute(attribute: "description", value: "Clients sending negotiation requests with invalid flags
could crash the kerberos server (CVE-2009-0845).

GSS-API clients could crash when reading from an invalid
address space (CVE-2009-0844).

Invalid length checks could crash applications using the
kerberos ASN.1 parser (CVE-2009-0847).

Under certain circumstances the ASN.1 parser could free an
uninitialized pointer which could crash a kerberos server
or even lead to execution of arbitrary code (CVE-2009-0846).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch krb5-6139");
script_end_attributes();

script_cve_id("CVE-2009-0845", "CVE-2009-0844", "CVE-2009-0847", "CVE-2009-0846");
script_summary(english: "Check for the krb5-6139 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"krb5-1.6.2-22.9", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"krb5-32bit-1.6.2-22.9", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"krb5-64bit-1.6.2-22.9", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"krb5-apps-clients-1.6.2-22.9", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"krb5-apps-servers-1.6.2-22.9", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"krb5-client-1.6.2-22.9", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"krb5-devel-1.6.2-22.9", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"krb5-devel-32bit-1.6.2-22.9", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"krb5-devel-64bit-1.6.2-22.9", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"krb5-server-1.6.2-22.9", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
