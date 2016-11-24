
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(34692);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  spamassassin: removed DNS_FROM_SECURITYSAGE scoring (perl-spamassassin-5736)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch perl-spamassassin-5736");
 script_set_attribute(attribute: "description", value: "Spamassassin tagged all incoming mails with
DNS_FROM_SECURITYSAGE=1.513 The reason is:  The
securityusage blacklist was disabled and replies with
127.0.0.1 to *all* queries.

This update removes this rule.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch perl-spamassassin-5736");
script_end_attributes();

script_summary(english: "Check for the perl-spamassassin-5736 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"perl-spamassassin-3.2.3-10.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"spamassassin-3.2.3-10.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
