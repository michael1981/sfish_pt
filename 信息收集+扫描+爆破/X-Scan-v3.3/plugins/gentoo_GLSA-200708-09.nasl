# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200708-09.xml
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
 script_id(25888);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200708-09");
 script_cve_id("CVE-2007-3089", "CVE-2007-3656", "CVE-2007-3734", "CVE-2007-3735", "CVE-2007-3736", "CVE-2007-3737", "CVE-2007-3738", "CVE-2007-3844");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200708-09 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200708-09
(Mozilla products: Multiple vulnerabilities)


    Mozilla developers fixed several bugs, including an issue with
    modifying XPCNativeWrappers (CVE-2007-3738), a problem with event
    handlers executing elements outside of the document (CVE-2007-3737),
    and a cross-site scripting (XSS) vulnerability (CVE-2007-3736). They
    also fixed a problem with promiscuous IFRAME access (CVE-2007-3089) and
    an XULRunner URL spoofing issue with the wyciwyg:// URI and HTTP 302
    redirects (CVE-2007-3656). Denials of Service involving corrupted
    memory were fixed in the browser engine (CVE-2007-3734) and the
    JavaScript engine (CVE-2007-3735). Finally, another XSS vulnerability
    caused by a regression in the CVE-2007-3089 patch was fixed
    (CVE-2007-3844).
  
Impact

    A remote attacker could entice a user to view a specially crafted web
    page that will trigger one of the vulnerabilities, possibly leading to
    the execution of arbitrary code or a Denial of Service. It is also
    possible for an attacker to perform cross-site scripting attacks, which
    could result in the exposure of sensitive information such as login
    credentials.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Mozilla Firefox users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/mozilla-firefox-2.0.0.6"
    All Mozilla Firefox binary users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/mozilla-firefox-bin-2.0.0.6"
    All Mozilla Thunderbird users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-client/mozilla-thunderbird-2.0.0.6"
    All Mozilla Thunderbird binary users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-client/mozilla-thunderbird-bin-2.0.0.6"
    All SeaMonkey users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/seamonkey-1.1.4"
    All SeaMonkey binary users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/seamonkey-bin-1.1.4"
    All XULRunner users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-libs/xulrunner-1.8.1.6"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3089');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3656');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3734');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3735');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3736');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3737');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3738');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3844');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200708-09.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200708-09] Mozilla products: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Mozilla products: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-libs/xulrunner", unaffected: make_list("ge 1.8.1.6"), vulnerable: make_list("lt 1.8.1.6")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "mail-client/mozilla-thunderbird-bin", unaffected: make_list("ge 2.0.0.6"), vulnerable: make_list("lt 2.0.0.6")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "www-client/mozilla-firefox-bin", unaffected: make_list("ge 2.0.0.6"), vulnerable: make_list("lt 2.0.0.6")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "www-client/seamonkey", unaffected: make_list("ge 1.1.4"), vulnerable: make_list("lt 1.1.4")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "mail-client/mozilla-thunderbird", unaffected: make_list("ge 2.0.0.6"), vulnerable: make_list("lt 2.0.0.6")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "www-client/seamonkey-bin", unaffected: make_list("ge 1.1.4"), vulnerable: make_list("lt 1.1.4")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "www-client/mozilla-firefox", unaffected: make_list("ge 2.0.0.6"), vulnerable: make_list("lt 2.0.0.6")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
