
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29543);
 script_version ("$Revision: 1.6 $");
 script_name(english: "SuSE Security Update:  Security update for OpenSSL (openssl-2175)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch openssl-2175");
 script_set_attribute(attribute: "description", value: "A previous openssl update (CVE-2006-2940) introduced
another bug that can lead to a crash by providing a large
prime number. An uninitialized pointer is freed during
error handling. This bug allows remote attackers to crash
services that use openssl.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch openssl-2175");
script_end_attributes();

script_cve_id("CVE-2006-2940");
script_summary(english: "Check for the openssl-2175 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"openssl-0.9.8a-18.13", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.8a-18.13", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"openssl-0.9.8a-18.13", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.8a-18.13", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
