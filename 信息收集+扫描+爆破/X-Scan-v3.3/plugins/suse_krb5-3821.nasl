
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29493);
 script_version ("$Revision: 1.10 $");
 script_name(english: "SuSE Security Update:  Security update for krb5 (krb5-3821)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch krb5-3821");
 script_set_attribute(attribute: "description", value: "This update fixes a stack-based buffer overflow in kadmind
which can be exploited by authenticated remote users to
gain root. (CVE-2007-2798) Additionally two bugs in the RPC
library of kadmind were fixed that can lead to remote
system compromise. (CVE-2007-2442, CVE-2007-2443) Note that
third-party applications using the RPC library are
vulnerable, too.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch krb5-3821");
script_end_attributes();

script_cve_id("CVE-2007-2442", "CVE-2007-2443", "CVE-2007-2798");
script_summary(english: "Check for the krb5-3821 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"krb5-1.4.3-19.22", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"krb5-devel-1.4.3-19.22", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"krb5-server-1.4.3-19.22", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"krb5-1.4.3-19.22", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"krb5-devel-1.4.3-19.22", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
