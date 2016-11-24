# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200408-22.xml
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
 script_id(14578);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200408-22");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200408-22 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200408-22
(Mozilla, Firefox, Thunderbird, Galeon, Epiphany: New releases fix vulnerabilities)


    Mozilla, Galeon, Epiphany, Mozilla Firefox and Mozilla Thunderbird
    contain the following vulnerabilities:
    All Mozilla tools use libpng for graphics. This library contains a
    buffer overflow which may lead to arbitrary code execution.
    If a user imports a forged Certificate Authority (CA) certificate,
    it may overwrite and corrupt the valid CA already installed on the
    machine.
    Mozilla, Mozilla Firefox, and other gecko-based browsers also contain a
    bug in their caching which may allow the SSL icon to remain visible,
    even when the site in question is an insecure site.
  
Impact

    Users of Mozilla, Mozilla Firefox, and other gecko-based browsers are
    susceptible to SSL certificate spoofing, a Denial of Service against
    legitimate SSL sites, crashes, and arbitrary code execution. Users of
    Mozilla Thunderbird are susceptible to crashes and arbitrary code
    execution via malicious e-mails.
  
Workaround

    There is no known workaround for most of these vulnerabilities. All
    users are advised to upgrade to the latest available version.
  
');
script_set_attribute(attribute:'solution', value: '
    All users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv your-version
    # emerge your-version
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0763');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0758');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0597');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0598');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0599');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200408-22.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200408-22] Mozilla, Firefox, Thunderbird, Galeon, Epiphany: New releases fix vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Mozilla, Firefox, Thunderbird, Galeon, Epiphany: New releases fix vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-client/galeon", unaffected: make_list("ge 1.3.17"), vulnerable: make_list("lt 1.3.17")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "mail-client/mozilla-thunderbird-bin", unaffected: make_list("ge 0.7.3"), vulnerable: make_list("lt 0.7.3")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "www-client/mozilla-firefox-bin", unaffected: make_list("ge 0.9.3"), vulnerable: make_list("lt 0.9.3")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "www-client/mozilla", unaffected: make_list("ge 1.7.2"), vulnerable: make_list("lt 1.7.2")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "mail-client/mozilla-thunderbird", unaffected: make_list("ge 0.7.3"), vulnerable: make_list("lt 0.7.3")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "www-client/mozilla-bin", unaffected: make_list("ge 1.7.2"), vulnerable: make_list("lt 1.7.2")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "www-client/mozilla-firefox", unaffected: make_list("ge 0.9.3"), vulnerable: make_list("lt 0.9.3")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "www-client/epiphany", unaffected: make_list("ge 1.2.7-r1"), vulnerable: make_list("lt 1.2.7-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
