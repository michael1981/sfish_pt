
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-1783
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(31124);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2008-1783: pcre");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-1783 (pcre)");
 script_set_attribute(attribute: "description", value: "Perl-compatible regular expression library.
PCRE has its own native API, but a set of 'wrapper' functions that are based on
the POSIX API are also supplied in the library libpcreposix. Note that this
just provides a POSIX calling interface to PCRE: the regular expressions
themselves still follow Perl syntax and semantics. The header file
for the POSIX-style functions is called pcreposix.h.

-
Update Information:

This update addresses buffer overflow caused by a character class containing a
very large number of characters with codepoints greater than 255 (in UTF-8 mode
)
- CVE-2008-0674, #431660    This issue may affect usages of pcre, when regular
expressions from untrusted sources are compiled.  Handling of untrusted data
using trusted regular expressions is not affected by this problem.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-0674");
script_summary(english: "Check for the version of the pcre package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"pcre-7.3-3.fc8", release:"FC8") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
