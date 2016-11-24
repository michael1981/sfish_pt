# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200712-21.xml
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
 script_id(29818);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200712-21");
 script_cve_id("CVE-2007-5947", "CVE-2007-5959", "CVE-2007-5960");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200712-21 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200712-21
(Mozilla Firefox, SeaMonkey: Multiple vulnerabilities)


    Jesse Ruderman and Petko D. Petkov reported that the jar protocol
    handler in Mozilla Firefox and Seamonkey does not properly check MIME
    types (CVE-2007-5947). Gregory Fleischer reported that the
    window.location property can be used to generate a fake HTTP Referer
    (CVE-2007-5960). Multiple memory errors have also been reported
    (CVE-2007-5959).
  
Impact

    A remote attacker could possibly exploit these vulnerabilities to
    execute arbitrary code in the context of the browser and conduct
    Cross-Site-Scripting or Cross-Site Request Forgery attacks.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Mozilla Firefox users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/mozilla-firefox-2.0.0.11"
    All Mozilla Firefox binary users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/mozilla-firefox-bin-2.0.0.11"
    All SeaMonkey users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/seamonkey-1.1.7"
    All SeaMonkey binary users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/seamonkey-bin-1.1.7"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5947');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5959');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5960');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200712-21.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200712-21] Mozilla Firefox, SeaMonkey: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Mozilla Firefox, SeaMonkey: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-client/mozilla-firefox-bin", unaffected: make_list("ge 2.0.0.11"), vulnerable: make_list("lt 2.0.0.11")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "www-client/seamonkey", unaffected: make_list("ge 1.1.7"), vulnerable: make_list("lt 1.1.7")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "www-client/seamonkey-bin", unaffected: make_list("ge 1.1.7"), vulnerable: make_list("lt 1.1.7")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "www-client/mozilla-firefox", unaffected: make_list("ge 2.0.0.11"), vulnerable: make_list("lt 2.0.0.11")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
