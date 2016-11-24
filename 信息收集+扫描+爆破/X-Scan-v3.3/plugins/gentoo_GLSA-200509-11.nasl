# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200509-11.xml
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
 script_id(19810);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200509-11");
 script_cve_id("CVE-2005-2701", "CVE-2005-2702", "CVE-2005-2703", "CVE-2005-2704", "CVE-2005-2705", "CVE-2005-2706", "CVE-2005-2707", "CVE-2005-2871");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200509-11 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200509-11
(Mozilla Suite, Mozilla Firefox: Multiple vulnerabilities)


    The Mozilla Suite and Firefox are both vulnerable to the following
    issues:
    Tom Ferris reported a heap overflow in IDN-enabled browsers with
    malicious Host: headers (CAN-2005-2871).
    "jackerror" discovered a heap overrun in XBM image processing
    (CAN-2005-2701).
    Mats Palmgren reported a potentially exploitable stack corruption
    using specific Unicode sequences (CAN-2005-2702).
    Georgi Guninski discovered an integer overflow in the JavaScript
    engine (CAN-2005-2705)
    Other issues ranging from DOM object spoofing to request header
    spoofing were also found and fixed in the latest versions
    (CAN-2005-2703, CAN-2005-2704, CAN-2005-2706, CAN-2005-2707).
    The Gecko engine in itself is also affected by some of these issues and
    has been updated as well.
  
Impact

    A remote attacker could setup a malicious site and entice a victim to
    visit it, potentially resulting in arbitrary code execution with the
    victim\'s privileges or facilitated spoofing of known websites.
  
Workaround

    There is no known workaround for all the issues.
  
');
script_set_attribute(attribute:'solution', value: '
    All Mozilla Firefox users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/mozilla-firefox-1.0.7-r2"
    All Mozilla Suite users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/mozilla-1.7.12-r2"
    All Mozilla Firefox binary users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/mozilla-firefox-bin-1.0.7"
    All Mozilla Suite binary users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/mozilla-bin-1.7.12"
    All Gecko library users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-libs/gecko-sdk-1.7.12"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-2701');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-2702');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-2703');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-2704');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-2705');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-2706');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-2707');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-2871');
script_set_attribute(attribute: 'see_also', value: 'http://www.mozilla.org/projects/security/known-vulnerabilities.html');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200509-11.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200509-11] Mozilla Suite, Mozilla Firefox: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Mozilla Suite, Mozilla Firefox: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-client/mozilla-firefox-bin", unaffected: make_list("ge 1.0.7"), vulnerable: make_list("lt 1.0.7")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "www-client/mozilla", unaffected: make_list("ge 1.7.12-r2"), vulnerable: make_list("lt 1.7.12-r2")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "net-libs/gecko-sdk", unaffected: make_list("ge 1.7.12"), vulnerable: make_list("lt 1.7.12")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "www-client/mozilla-bin", unaffected: make_list("ge 1.7.12"), vulnerable: make_list("lt 1.7.12")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "www-client/mozilla-firefox", unaffected: make_list("ge 1.0.7-r2"), vulnerable: make_list("lt 1.0.7-r2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
