# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200703-08.xml
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
 script_id(24800);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200703-08");
 script_cve_id("CVE-2006-6077", "CVE-2007-0775", "CVE-2007-0776", "CVE-2007-0777", "CVE-2007-0778", "CVE-2007-0779", "CVE-2007-0780", "CVE-2007-0800", "CVE-2007-0801", "CVE-2007-0981", "CVE-2007-0995");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200703-08 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200703-08
(SeaMonkey: Multiple vulnerabilities)


    Tom Ferris reported a heap-based buffer overflow involving wide SVG
    stroke widths that affects SeaMonkey. Various researchers reported some
    errors in the JavaScript engine potentially leading to memory
    corruption. SeaMonkey also contains minor vulnerabilities involving
    cache collision and unsafe pop-up restrictions, filtering or CSS
    rendering under certain conditions. All those vulnerabilities are the
    same as in GLSA 200703-04 affecting Mozilla Firefox.
  
Impact

    An attacker could entice a user to view a specially crafted web page or
    to read a specially crafted email that will trigger one of the
    vulnerabilities, possibly leading to the execution of arbitrary code.
    It is also possible for an attacker to spoof the address bar, steal
    information through cache collision, bypass the local file protection
    mechanism with pop-ups, or perform cross-site scripting attacks,
    leading to the exposure of sensitive information, such as user
    credentials.
  
Workaround

    There is no known workaround at this time for all of these issues, but
    most of them can be avoided by disabling JavaScript. Note that the
    execution of JavaScript is disabled by default in the SeaMonkey email
    client, and enabling it is strongly discouraged.
  
');
script_set_attribute(attribute:'solution', value: '
    Users upgrading to the following release of SeaMonkey should note that
    the corresponding Mozilla Firefox upgrade has been found to lose the
    saved passwords file in some cases. The saved passwords are encrypted
    and stored in the \'signons.txt\' file of ~/.mozilla/ and we advise our
    users to save that file before performing the upgrade.
    All SeaMonkey users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/seamonkey-1.1.1"
    All SeaMonkey binary users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/seamonkey-bin-1.1.1"
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

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200703-08.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200703-08] SeaMonkey: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'SeaMonkey: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-client/seamonkey", unaffected: make_list("ge 1.1.1"), vulnerable: make_list("lt 1.1.1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "www-client/seamonkey-bin", unaffected: make_list("ge 1.1.1"), vulnerable: make_list("lt 1.1.1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
