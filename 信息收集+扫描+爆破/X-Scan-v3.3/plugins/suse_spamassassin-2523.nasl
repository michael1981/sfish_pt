
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27450);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  spamassassin: Versionsupdate to version 3.1.7 (spamassassin-2523)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch spamassassin-2523");
 script_set_attribute(attribute: "description", value: "Primary it is a version update for the packages
spamassassin und perl-spamassasin to version 3.1.7.

Furthermore the following bugs were fixed: 

- SpamAssassin URIDNSBL plugin tries to lookup libraries
  (libimf.so,
 liblua.so, ...) via nameserver
- BUG in archive PgSQL.pm (SpamAssassin)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch spamassassin-2523");
script_end_attributes();

script_summary(english: "Check for the spamassassin-2523 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"perl-spamassassin-3.1.7-6.1", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"spamassassin-3.1.7-6.1", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
