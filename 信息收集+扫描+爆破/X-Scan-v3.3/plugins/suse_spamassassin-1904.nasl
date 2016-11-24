
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27449);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  spamassassin: Securityfix for potential remote root exploit. (spamassassin-1904)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch spamassassin-1904");
 script_set_attribute(attribute: "description", value: "This update fixes the following security problem in
SpamAssassin:
- CVE-2006-2447: SpamAssassin when running with vpopmail
  and the paranoid (-P) switch, allows remote attackers to
  execute arbitrary commands via a crafted message that is
  not properly handled when invoking spamd with the virtual
  pop username.

At the same time we upgraded SpamAssassin to version 3.1.3,
bringing lots of bug fixes and new rules.

Please make sure you verify that it still works with your
configuration.

Also included is now 'sa-update', a rule update script. For
this script to work make sure that the perl-IO-ZLib and
perl-libwww-perl packages are installed.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch spamassassin-1904");
script_end_attributes();

script_cve_id("CVE-2006-2447");
script_summary(english: "Check for the spamassassin-1904 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"perl-spamassassin-3.1.3-3.2", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"spamassassin-3.1.3-3.2", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
