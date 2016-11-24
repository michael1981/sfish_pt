# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200805-18.xml
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
 script_id(32416);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200805-18");
 script_cve_id("CVE-2007-4879", "CVE-2008-0304", "CVE-2008-0412", "CVE-2008-0413", "CVE-2008-0414", "CVE-2008-0415", "CVE-2008-0416", "CVE-2008-0417", "CVE-2008-0418", "CVE-2008-0419", "CVE-2008-0420", "CVE-2008-0591", "CVE-2008-0592", "CVE-2008-0593", "CVE-2008-0594", "CVE-2008-1233", "CVE-2008-1234", "CVE-2008-1235", "CVE-2008-1236", "CVE-2008-1237", "CVE-2008-1238", "CVE-2008-1240", "CVE-2008-1241", "CVE-2008-1380");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200805-18 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200805-18
(Mozilla products: Multiple vulnerabilities)

Impact

    A remote attacker could entice a user to view a specially crafted web
    page or email that will trigger one of the vulnerabilities, possibly
    leading to the execution of arbitrary code or a Denial of Service. It
    is also possible for an attacker to trick a user to upload arbitrary
    files when submitting a form, to corrupt saved passwords for other
    sites, to steal login credentials, or to conduct Cross-Site Scripting
    and Cross-Site Request Forgery attacks.
  
Workaround

    There is no known workaround at this time.
  

');
script_set_attribute(attribute:'solution', value: '
    All Mozilla Firefox users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/mozilla-firefox-2.0.0.14"
    All Mozilla Firefox binary users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/mozilla-firefox-bin-2.0.0.14"
    All Mozilla Thunderbird users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-client/mozilla-thunderbird-2.0.0.14"
    All Mozilla Thunderbird binary users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-client/mozilla-thunderbird-bin-2.0.0.14"
    All SeaMonkey users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/seamonkey-1.1.9-r1"
    All SeaMonkey binary users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/seamonkey-bin-1.1.9"
    All XULRunner users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-libs/xulrunner-1.8.1.14"
    NOTE: The crash vulnerability (CVE-2008-1380) is currently unfixed in
    the SeaMonkey binary ebuild, as no precompiled packages have been
    released. Until an update is available, we recommend all SeaMonkey
    users to disable JavaScript, use Firefox for JavaScript-enabled
    browsing, or switch to the SeaMonkey source ebuild.
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4879');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0304');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0412');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0413');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0414');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0415');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0416');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0417');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0418');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0419');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0420');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0591');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0592');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0593');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0594');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1233');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1234');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1235');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1236');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1237');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1238');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1240');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1241');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1380');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200805-18.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200805-18] Mozilla products: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Mozilla products: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-libs/xulrunner", unaffected: make_list("ge 1.8.1.14"), vulnerable: make_list("lt 1.8.1.14")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "mail-client/mozilla-thunderbird-bin", unaffected: make_list("ge 2.0.0.14"), vulnerable: make_list("lt 2.0.0.14")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "www-client/mozilla-firefox-bin", unaffected: make_list("ge 2.0.0.14"), vulnerable: make_list("lt 2.0.0.14")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "www-client/seamonkey", unaffected: make_list("ge 1.1.9-r1"), vulnerable: make_list("lt 1.1.9-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "mail-client/mozilla-thunderbird", unaffected: make_list("ge 2.0.0.14"), vulnerable: make_list("lt 2.0.0.14")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "www-client/seamonkey-bin", unaffected: make_list("ge 1.1.9"), vulnerable: make_list("lt 1.1.9")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "www-client/mozilla-firefox", unaffected: make_list("ge 2.0.0.14"), vulnerable: make_list("lt 2.0.0.14")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
