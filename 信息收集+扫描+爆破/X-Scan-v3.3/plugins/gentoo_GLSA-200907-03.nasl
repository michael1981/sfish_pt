# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200907-03.xml
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
 script_id(39614);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200907-03");
 script_cve_id("CVE-2009-0023", "CVE-2009-1955", "CVE-2009-1956");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200907-03 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200907-03
(APR Utility Library: Multiple vulnerabilities)


    Multiple vulnerabilities have been discovered in the APR Utility
    Library:
    Matthew Palmer reported a heap-based buffer
    underflow while compiling search patterns in the
    apr_strmatch_precompile() function in strmatch/apr_strmatch.c
    (CVE-2009-0023).
    kcope reported that the expat XML parser in
    xml/apr_xml.c does not limit the amount of XML entities expanded
    recursively (CVE-2009-1955).
    C. Michael Pilato reported an
    off-by-one error in the apr_brigade_vprintf() function in
    buckets/apr_brigade.c (CVE-2009-1956).
  
Impact

    A remote attacker could exploit these vulnerabilities to cause a Denial
    of Service (crash or memory exhaustion) via an Apache HTTP server
    running mod_dav or mod_dav_svn, or using several configuration files.
    Additionally, a remote attacker could disclose sensitive information or
    cause a Denial of Service by sending a specially crafted input. NOTE:
    Only big-endian architectures such as PPC and HPPA are affected by the
    latter flaw.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Apache Portable Runtime Utility Library users should upgrade to the
    latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-libs/apr-util-1.3.7"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0023');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1955');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1956');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200907-03.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200907-03] APR Utility Library: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'APR Utility Library: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-libs/apr-util", unaffected: make_list("ge 1.3.7"), vulnerable: make_list("lt 1.3.7")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
