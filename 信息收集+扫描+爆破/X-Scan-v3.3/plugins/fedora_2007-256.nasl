
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-256
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24728);
 script_version ("$Revision: 1.4 $");
script_name(english: "Fedora 6 2007-256: gnucash");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-256 (gnucash)");
 script_set_attribute(attribute: "description", value: "GnuCash is a personal finance manager. A check-book like register GUI
allows you to enter and track bank accounts, stocks, income and even
currency trades. The interface is designed to be simple and easy to
use, but is backed with double-entry accounting principles to ensure
balanced books.

Update Information:

This updates GnuCash to version 2.0.5, the latest upstream
release.

Major changes in this release include;
o Fix some strings not being translated.
o Use guiles native sort and record.
o Adjust how payment dialog resizes.
o Don't abort when F::Q fails to return a quote.
o Change Russian Ruble from RUR to RUB.
o Fix security problem with tmp filesystem and symlink
attack. (CVE-2007-0007)
o Add French and Canadian French translation updates.
o Do not crash on delete_event in new user dialog.
o Add sanity checks when accessing GncPluginPage.
o Make new windows the same size as the active one.
o The New Turkish Lira changed from TRL to TRY in 2005.

Thanks to Sami Farin for uncovering the /tmp file issue.

");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-0007");
script_summary(english: "Check for the version of the gnucash package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"gnucash-2.0.5-1.fc6", release:"FC6") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
