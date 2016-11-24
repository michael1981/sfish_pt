# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-03.xml
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
 script_id(16394);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200501-03");
 script_cve_id("CVE-2004-2227", "CVE-2004-2228");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200501-03 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200501-03
(Mozilla, Firefox, Thunderbird: Various vulnerabilities)


    Maurycy Prodeus from isec.pl found a potentially exploitable buffer
    overflow in the handling of NNTP URLs. Furthermore, Martin (from
    ptraced.net) discovered that temporary files in recent versions of
    Mozilla-based products were sometimes stored world-readable with
    predictable names. The Mozilla Team also fixed a way of spoofing
    filenames in Firefox\'s "What should Firefox do with this file" dialog
    boxes and a potential information leak about the existence of local
    filenames.
  
Impact

    A remote attacker could craft a malicious NNTP link and entice a user
    to click it, potentially resulting in the execution of arbitrary code
    with the rights of the user running the browser. A local attacker could
    leverage the temporary file vulnerability to read the contents of
    another user\'s attachments or downloads. A remote attacker could also
    design a malicious web page that would allow to spoof filenames if the
    user uses the "Open with..." function in Firefox, or retrieve
    information on the presence of specific files in the local filesystem.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Mozilla users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/mozilla-1.7.5"
    All Mozilla binary users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/mozilla-bin-1.7.5"
    All Firefox users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/mozilla-firefox-1.0"
    All Firefox binary users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/mozilla-firefox-bin-1.0"
    All Thunderbird users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-client/mozilla-thunderbird-0.9"
    All Thunderbird binary users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-client/mozilla-thunderbird-bin-0.9"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://isec.pl/vulnerabilities/isec-0020-mozilla.txt');
script_set_attribute(attribute: 'see_also', value: 'http://broadcast.ptraced.net/advisories/008-firefox.thunderbird.txt');
script_set_attribute(attribute: 'see_also', value: 'http://secunia.com/advisories/13144/');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-2227');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-2228');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200501-03.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200501-03] Mozilla, Firefox, Thunderbird: Various vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Mozilla, Firefox, Thunderbird: Various vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "mail-client/mozilla-thunderbird-bin", unaffected: make_list("ge 0.9"), vulnerable: make_list("lt 0.9")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "www-client/mozilla-firefox-bin", unaffected: make_list("ge 1.0"), vulnerable: make_list("lt 1.0")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "www-client/mozilla", unaffected: make_list("ge 1.7.5"), vulnerable: make_list("lt 1.7.5")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "mail-client/mozilla-thunderbird", unaffected: make_list("ge 0.9"), vulnerable: make_list("lt 0.9")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "www-client/mozilla-firefox", unaffected: make_list("ge 1.0"), vulnerable: make_list("lt 1.0")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "www-client/mozilla-bin", unaffected: make_list("ge 1.7.5"), vulnerable: make_list("lt 1.7.5")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
