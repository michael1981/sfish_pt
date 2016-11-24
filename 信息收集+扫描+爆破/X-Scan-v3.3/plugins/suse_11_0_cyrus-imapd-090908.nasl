
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41034);
 script_version("$Revision: 1.1 $");
 script_name(english: "SuSE 11.0 Security Update:  cyrus-imapd (2009-09-08)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for cyrus-imapd");
 script_set_attribute(attribute: "description", value: "This update of cyrus-imapd fixes a buffer overflow that
occurs in snprintf() due to incorrectly calculating the
size of the destination buffer. (CVE-2009-2632)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for cyrus-imapd");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=537128");
script_end_attributes();

 script_cve_id("CVE-2009-2632");
script_summary(english: "Check for the cyrus-imapd package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"cyrus-imapd-2.3.11-31.2", release:"SUSE11.0", cpu:"i586") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-2.3.11-31.2", release:"SUSE11.0", cpu:"x86_64") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-devel-2.3.11-31.2", release:"SUSE11.0", cpu:"i586") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-devel-2.3.11-31.2", release:"SUSE11.0", cpu:"x86_64") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"perl-Cyrus-IMAP-2.3.11-31.2", release:"SUSE11.0", cpu:"i586") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"perl-Cyrus-IMAP-2.3.11-31.2", release:"SUSE11.0", cpu:"x86_64") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"perl-Cyrus-SIEVE-managesieve-2.3.11-31.2", release:"SUSE11.0", cpu:"i586") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"perl-Cyrus-SIEVE-managesieve-2.3.11-31.2", release:"SUSE11.0", cpu:"x86_64") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");
