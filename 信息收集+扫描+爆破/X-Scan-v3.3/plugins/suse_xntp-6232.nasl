
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41601);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  Security update for xntp (xntp-6232)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch xntp-6232");
 script_set_attribute(attribute: "description", value: "This update fixes a remote buffer overflow in xntp/ntp
which can be exploited when autokey is enabled to execute
arbitrary code. (CVE-2009-1252) This upfate fixes a buffer
overflow in ntpd that can be triggered by a malicious
server. (CVE-2009-0159)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch xntp-6232");
script_end_attributes();

script_cve_id("CVE-2009-0159", "CVE-2009-1252");
script_summary(english: "Check for the xntp-6232 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"xntp-4.2.4p3-48.13.3", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"xntp-doc-4.2.4p3-48.13.3", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
