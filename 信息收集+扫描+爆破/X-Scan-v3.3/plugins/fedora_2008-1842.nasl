
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-1842
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(31363);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2008-1842: pcre");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-1842 (pcre)");
 script_set_attribute(attribute: "description", value: "Perl-compatible regular expression library.
PCRE has its own native API, but a set of 'wrapper' functions that are based on
the POSIX API are also supplied in the library libpcreposix. Note that this
just provides a POSIX calling interface to PCRE: the regular expressions
themselves still follow Perl syntax and semantics. The header file
for the POSIX-style functions is called pcreposix.h.

-
Update Information:

This update re-based pcre to version 7.3 as used in Fedora 8 to address multipl
e
security issues that cause memory corruption, leading to application crash or
possible execution of arbitrary code.    CVE-2007-1659 (#315871), CVE-2007-1661
(#392931), CVE-2007-1662 (#392921), CVE-2007-4766 (#392891), CVE-2007-4767
(#392901), CVE-2007-4768 (#392911), CVE-2008-0674 (#431660)    This issue may
affect usages of pcre, where regular expressions from untrusted sources are
compiled.  Handling of untrusted data using trusted regular expressions is not
affected by these problems.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-1659", "CVE-2007-1661", "CVE-2007-1662", "CVE-2007-4766", "CVE-2007-4767", "CVE-2007-4768", "CVE-2008-0674");
script_summary(english: "Check for the version of the pcre package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"pcre-7.3-3.fc7", release:"FC7") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
