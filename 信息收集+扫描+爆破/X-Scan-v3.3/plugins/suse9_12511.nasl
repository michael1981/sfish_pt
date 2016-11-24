
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41954);
 script_version("$Revision: 1.1 $");
 script_name(english: "SuSE9 Security Update:  Security update for IBM Java2 JRE and SDK (12511)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE9 system is missing the security patch 12511");
 script_set_attribute(attribute: "description", value: 'IBM Java 1.4.2 was updated to SR13 FP1.
It fixes following two security issues:
CVE-2009-2625: A vulnerability in the Java Runtime Environment (JRE) with
parsing XML data might allow a remote client to create a denial-of-service
condition on the system that the JRE runs on.
CVE-2008-5349: A vulnerability in how the Java Runtime Environment (JRE)
handles certain RSA public keys might cause the JRE to consume an excessive
amount of CPU resources. This might lead to a Denial of Service (DoS)
condition on affected systems. Such keys could be provided by a remote client
of an application. 
This issue affects the following security providers: IBMJCE, IBMPKCS11Impl and
IBMJCEFIPS.
');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch 12511");
script_end_attributes();

script_cve_id("CVE-2008-5349","CVE-2009-2625");
script_summary(english: "Check for the security advisory #12511");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"IBMJava2-JRE-1.4.2-0.144", release:"SUSE9", cpu: "i586") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"IBMJava2-SDK-1.4.2-0.144", release:"SUSE9", cpu: "i586") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
