# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200708-13.xml
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
 script_id(25919);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200708-13");
 script_cve_id("CVE-2007-2925", "CVE-2007-2926");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200708-13 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200708-13
(BIND: Weak random number generation)


    Amit Klein from Trusteer reported that the random number generator of
    ISC BIND leads, half the time, to predictable (1 chance to 8) query IDs
    in the resolver routine or in zone transfer queries (CVE-2007-2926).
    Additionally, the default configuration file has been strengthen with
    respect to the allow-recursion{} and the allow-query{} options
    (CVE-2007-2925).
  
Impact

    A remote attacker can use this weakness by sending queries for a domain
    he handles to a resolver (directly to a recursive server, or through
    another process like an email processing) and then observing the
    resulting IDs of the iterative queries. The attacker will half the time
    be able to guess the next query ID, then perform cache poisoning by
    answering with those guessed IDs, while spoofing the UDP source address
    of the reply. Furthermore, with empty allow-recursion{} and
    allow-query{} options, the default configuration allowed anybody to
    make recursive queries and query the cache.
  
Workaround

    There is no known workaround at this time for the random generator
    weakness. The allow-recursion{} and allow-query{} options should be set
    to trusted hosts only in /etc/bind/named.conf, thus preventing several
    security risks.
  
');
script_set_attribute(attribute:'solution', value: '
    All ISC BIND users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-dns/bind-9.4.1_p1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-2925');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-2926');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200708-13.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200708-13] BIND: Weak random number generation');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'BIND: Weak random number generation');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-dns/bind", unaffected: make_list("ge 9.4.1_p1"), vulnerable: make_list("lt 9.4.1_p1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
