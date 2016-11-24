# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200504-15.xml
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
 script_id(18081);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200504-15");
 script_cve_id("CVE-2005-0524", "CVE-2005-0525", "CVE-2005-1042", "CVE-2005-1043");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200504-15 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200504-15
(PHP: Multiple vulnerabilities)


    An integer overflow and an unbound recursion were discovered in
    the processing of Image File Directory tags in PHP\'s EXIF module
    (CAN-2005-1042, CAN-2005-1043). Furthermore, two infinite loops have
    been discovered in the getimagesize() function when processing IFF or
    JPEG images (CAN-2005-0524, CAN-2005-0525).
  
Impact

    A remote attacker could craft an image file with a malicious EXIF
    IFD tag, a large IFD nesting level or invalid size parameters and send
    it to a web application that would process this user-provided image
    using one of the affected functions. This could result in denying
    service on the attacked server and potentially executing arbitrary code
    with the rights of the web server.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All PHP users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-php/php-4.3.11"
    All mod_php users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-php/mod_php-4.3.11"
    All php-cgi users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-php/php-cgi-4.3.11"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.php.net/release_4_3_11.php');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0524');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0525');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-1042');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-1043');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200504-15.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200504-15] PHP: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PHP: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-php/php-cgi", unaffected: make_list("ge 4.3.11"), vulnerable: make_list("lt 4.3.11")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "dev-php/php", unaffected: make_list("ge 4.3.11"), vulnerable: make_list("lt 4.3.11")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "dev-php/mod_php", unaffected: make_list("ge 4.3.11"), vulnerable: make_list("lt 4.3.11")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
