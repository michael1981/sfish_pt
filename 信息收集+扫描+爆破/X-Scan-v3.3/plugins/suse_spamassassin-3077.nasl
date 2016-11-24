
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27451);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  spamassassin: Security and bugfix update to version 3.1.8 (spamassassin-3077)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch spamassassin-3077");
 script_set_attribute(attribute: "description", value: "This upgrade brings spamassassin to version 3.1.8 with
following changes:

* fix for CVE-2007-0451: possible DoS due to incredibly
  long URIs found in the message content.
* disable perl module usage in update channels unless
  --allowplugins is specified
* files with names starting/ending in whitespace weren't
  usable
* remove Text::Wrap related code due to upstream issues
* update spamassassin and sa-learn to better deal with STDIN
* improvements and bug fixes related to DomainKeys and DKIM
  support
* several updates for Received header parsing
* several documentation updates and random taint-variable
  related issues

This update also adds some missing dependencies.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch spamassassin-3077");
script_end_attributes();

script_cve_id("CVE-2007-0451");
script_summary(english: "Check for the spamassassin-3077 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"perl-spamassassin-3.1.8-9.1", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"spamassassin-3.1.8-9.1", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
