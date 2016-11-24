
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2006-788
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24141);
 script_version ("$Revision: 1.4 $");
script_name(english: "Fedora 5 2006-788: squirrelmail");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2006-788 (squirrelmail)");
 script_set_attribute(attribute: "description", value: "SquirrelMail is a standards-based webmail package written in PHP4. It
includes built-in pure PHP support for the IMAP and SMTP protocols, and
all pages render in pure HTML 4.0 (with no Javascript) for maximum
compatibility across browsers.  It has very few requirements and is very
easy to configure and install. SquirrelMail has all the functionality
you would want from an email client, including strong MIME support,
address books, and folder manipulation.

Update Information:

Many fixes here.  Please report any regressions to Red Hat
Bugzilla.

- 1.4.7 with CVE-2006-3174 (#197369)
- Move sqspell_config.php to /etc and mark it
%%config(noreplace) (#192236)
- Reduce patch for body text (#194457)
- Better JP translation for 'Check mail' (#196117)
- Japanese zenkaku subject conversion      (#196017)
- Japanese MSIE garbled download ugly hack (#195639)
- Japanese multibyte attachment view text  (#195452)
- Japanese multibyte attachment body text  (#194457)
- Do not convert Japanese Help to UTF-8    (#194599)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2006-2842", "CVE-2006-3174");
script_summary(english: "Check for the version of the squirrelmail package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"squirrelmail-1.4.7-2.fc5", release:"FC5") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
