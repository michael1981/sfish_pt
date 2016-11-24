
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(42302);
 script_version ("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  Security update for Cyrus IMAPD (cyrus-imapd-6509)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch cyrus-imapd-6509");
 script_set_attribute(attribute: "description", value: "This update fixes another buffer overflow in the Sieve code
(CVE-2009-3235). This can be exploited by users allowed to
use their own sieve scripts to execute arbitrary code
remotely. Additionally the handling of long headers was
improved.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch cyrus-imapd-6509");
script_end_attributes();

script_cve_id("CVE-2009-3235");
script_summary(english: "Check for the cyrus-imapd-6509 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"cyrus-imapd-2.2.12-27.13.4", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-devel-2.2.12-27.13.4", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"perl-Cyrus-IMAP-2.2.12-27.13.4", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"perl-Cyrus-SIEVE-managesieve-2.2.12-27.13.4", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
