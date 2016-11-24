# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200703-04.xml
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
 script_id(24771);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200703-04");
 script_cve_id("CVE-2006-6077", "CVE-2007-0775", "CVE-2007-0776", "CVE-2007-0777", "CVE-2007-0778", "CVE-2007-0779", "CVE-2007-0780", "CVE-2007-0800", "CVE-2007-0801", "CVE-2007-0981", "CVE-2007-0995");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200703-04 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200703-04
(Mozilla Firefox: Multiple vulnerabilities)


    Tom Ferris reported a heap-based buffer overflow involving wide SVG
    stroke widths that affects Mozilla Firefox 2 only. Various researchers
    reported some errors in the JavaScript engine potentially leading to
    memory corruption. Mozilla Firefox also contains minor vulnerabilities
    involving cache collision and unsafe pop-up restrictions, filtering or
    CSS rendering under certain conditions.
  
Impact

    An attacker could entice a user to view a specially crafted web page
    that will trigger one of the vulnerabilities, possibly leading to the
    execution of arbitrary code. It is also possible for an attacker to
    spoof the address bar, steal information through cache collision,
    bypass the local files protection mechanism with pop-ups, or perform
    cross-site scripting attacks, leading to the exposure of sensitive
    information, like user credentials.
  
Workaround

    There is no known workaround at this time for all of these issues, but
    most of them can be avoided by disabling JavaScript.
  
');
script_set_attribute(attribute:'solution', value: '
    Users upgrading to the following releases of Mozilla Firefox should
    note that this upgrade has been found to lose the saved passwords file
    in some cases. The saved passwords are encrypted and stored in the
    \'signons.txt\' file of ~/.mozilla/ and we advise our users to save that
    file before performing the upgrade.
    All Mozilla Firefox 1.5 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/mozilla-firefox-1.5.0.10"
    All Mozilla Firefox 1.5 binary users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/mozilla-firefox-bin-1.5.0.10"
    All Mozilla Firefox 2.0 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/mozilla-firefox-2.0.0.2"
    All Mozilla Firefox 2.0 binary users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/mozilla-firefox-bin-2.0.0.2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-6077');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0775');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0776');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0777');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0778');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0779');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0780');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0800');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0801');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0981');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0995');
script_set_attribute(attribute: 'see_also', value: 'https://bugzilla.mozilla.org/show_bug.cgi?id=360493#c366');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200703-04.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200703-04] Mozilla Firefox: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Mozilla Firefox: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-client/mozilla-firefox-bin", unaffected: make_list("rge 1.5.0.10", "ge 2.0.0.2"), vulnerable: make_list("lt 2.0.0.2")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "www-client/mozilla-firefox", unaffected: make_list("rge 1.5.0.10", "ge 2.0.0.2"), vulnerable: make_list("lt 2.0.0.2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
