# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200811-05.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description)
{
 script_id(34787);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200811-05");
 script_cve_id("CVE-2008-0599", "CVE-2008-0674", "CVE-2008-1384", "CVE-2008-2050", "CVE-2008-2051", "CVE-2008-2107", "CVE-2008-2108", "CVE-2008-2371", "CVE-2008-2665", "CVE-2008-2666", "CVE-2008-2829", "CVE-2008-3658", "CVE-2008-3659", "CVE-2008-3660");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200811-05 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200811-05
(PHP: Multiple vulnerabilities)


    Several vulnerabilitites were found in PHP:
    PHP ships a
    vulnerable version of the PCRE library which allows for the
    circumvention of security restrictions or even for remote code
    execution in case of an application which accepts user-supplied regular
    expressions (CVE-2008-0674).
    Multiple crash issues in several
    PHP functions have been discovered.
    Ryan Permeh reported that
    the init_request_info() function in sapi/cgi/cgi_main.c does not
    properly consider operator precedence when calculating the length of
    PATH_TRANSLATED (CVE-2008-0599).
    An off-by-one error in the
    metaphone() function may lead to memory corruption.
    Maksymilian Arciemowicz of SecurityReason Research reported an
    integer overflow, which is triggerable using printf() and related
    functions (CVE-2008-1384).
    Andrei Nigmatulin reported a
    stack-based buffer overflow in the FastCGI SAPI, which has unknown
    attack vectors (CVE-2008-2050).
    Stefan Esser reported that PHP
    does not correctly handle multibyte characters inside the
    escapeshellcmd() function, which is used to sanitize user input before
    its usage in shell commands (CVE-2008-2051).
    Stefan Esser
    reported that a short-coming in PHP\'s algorithm of seeding the random
    number generator might allow for predictible random numbers
    (CVE-2008-2107, CVE-2008-2108).
    The IMAP extension in PHP uses
    obsolete c-client API calls making it vulnerable to buffer overflows as
    no bounds checking can be done (CVE-2008-2829).
    Tavis Ormandy
    reported a heap-based buffer overflow in pcre_compile.c in the PCRE
    version shipped by PHP when processing user-supplied regular
    expressions (CVE-2008-2371).
    CzechSec reported that specially
    crafted font files can lead to an overflow in the imageloadfont()
    function in ext/gd/gd.c, which is part of the GD extension
    (CVE-2008-3658).
    Maksymilian Arciemowicz of SecurityReason
    Research reported that a design error in PHP\'s stream wrappers allows
    to circumvent safe_mode checks in several filesystem-related PHP
    functions (CVE-2008-2665, CVE-2008-2666).
    Laurent Gaffie
    discovered a buffer overflow in the internal memnstr() function, which
    is used by the PHP function explode() (CVE-2008-3659).
    An
    error in the FastCGI SAPI when processing a request with multiple dots
    preceding the extension (CVE-2008-3660).
  
Impact

    These vulnerabilities might allow a remote attacker to execute
    arbitrary code, to cause a Denial of Service, to circumvent security
    restrictions, to disclose information, and to manipulate files.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All PHP users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-lang/php-5.2.6-r6"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0599');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0674');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1384');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2050');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2051');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2107');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2108');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2371');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2665');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2666');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2829');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3658');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3659');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3660');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200811-05.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200811-05] PHP: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PHP: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-lang/php", unaffected: make_list("ge 5.2.6-r6"), vulnerable: make_list("lt 5.2.6-r6")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
