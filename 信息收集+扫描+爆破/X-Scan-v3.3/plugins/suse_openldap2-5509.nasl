
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(34440);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  openldap2: Fix for liblber denial-of-service bug (openldap2-5509)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch openldap2-5509");
 script_set_attribute(attribute: "description", value: "This update fixes a security problem in the liblber client
library of openldap that allowed remote attackers to cause
a denial of service (program termination) via crafted ASN.1
BER datagrams, which triggers an assertion error.
(CVE-2008-2952) Additionally a bug was fixed in
ldap_free_connection which could result in client crashes
when the server closed a connection while an operation is
active.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch openldap2-5509");
script_end_attributes();

script_cve_id("CVE-2008-2952");
script_summary(english: "Check for the openldap2-5509 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"openldap2-2.3.37-7.8", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"openldap2-back-meta-2.3.37-7.8", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"openldap2-back-perl-2.3.37-7.8", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"openldap2-client-2.3.37-20.6", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"openldap2-client-32bit-2.3.37-20.6", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"openldap2-client-64bit-2.3.37-20.6", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"openldap2-devel-2.3.37-20.6", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"openldap2-devel-32bit-2.3.37-20.6", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"openldap2-devel-64bit-2.3.37-20.6", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
