# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200612-06.xml
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
 script_id(23858);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200612-06");
 script_cve_id("CVE-2006-5462", "CVE-2006-5463", "CVE-2006-5464", "CVE-2006-5747", "CVE-2006-5748");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200612-06 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200612-06
(Mozilla Thunderbird: Multiple vulnerabilities)


    It has been identified that Mozilla Thunderbird improperly handles
    Script objects while they are being executed, allowing them to be
    modified during execution. JavaScript is disabled in Mozilla
    Thunderbird by default. Mozilla Thunderbird has also been found to be
    vulnerable to various potential buffer overflows. Lastly, the binary
    release of Mozilla Thunderbird is vulnerable to a low exponent RSA
    signature forgery issue because it is bundled with a vulnerable version
    of NSS.
  
Impact

    An attacker could entice a user to view a specially crafted email that
    causes a buffer overflow and again executes arbitrary code or causes a
    Denial of Service. An attacker could also entice a user to view an
    email containing specially crafted JavaScript and execute arbitrary
    code with the rights of the user running Mozilla Thunderbird. It is
    important to note that JavaScript is off by default in Mozilla
    Thunderbird, and enabling it is strongly discouraged. It is also
    possible for an attacker to create SSL/TLS or email certificates that
    would not be detected as invalid by the binary release of Mozilla
    Thunderbird, raising the possibility for Man-in-the-Middle attacks.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    Users upgrading to the following releases of Mozilla Thunderbird should
    note that this version of Mozilla Thunderbird has been found to not
    display certain messages in some cases.
     All Mozilla Thunderbird users should upgrade to the
    latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-client/mozilla-thunderbird-1.5.0.8"
    All Mozilla Thunderbird binary release users should upgrade to the
    latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-client/mozilla-thunderbird-bin-1.5.0.8"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-5462');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-5463');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-5464');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-5747');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-5748');
script_set_attribute(attribute: 'see_also', value: 'https://bugzilla.mozilla.org/show_bug.cgi?id=360409');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200612-06.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200612-06] Mozilla Thunderbird: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Mozilla Thunderbird: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "mail-client/mozilla-thunderbird-bin", unaffected: make_list("ge 1.5.0.8"), vulnerable: make_list("lt 1.5.0.8")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "mail-client/mozilla-thunderbird", unaffected: make_list("ge 1.5.0.8"), vulnerable: make_list("lt 1.5.0.8")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
