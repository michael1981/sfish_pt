# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200407-15.xml
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
 script_id(14548);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200407-15");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200407-15 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200407-15
(Opera: Multiple spoofing vulnerabilities)


    Opera fails to remove illegal characters from an URI of a link and to check
    that the target frame of a link belongs to the same website as the link.
    Opera also updates the address bar before loading a page. Additionally,
    Opera contains a certificate verification problem.
  
Impact

    These vulnerabilities could allow an attacker to impersonate legitimate
    websites to steal sensitive information from users. This could be done by
    obfuscating the real URI of a link or by injecting a malicious frame into
    an arbitrary frame of another browser window.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version.
  
');
script_set_attribute(attribute:'solution', value: '
    All Opera users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=www-client/opera-7.53"
    # emerge ">=www-client/opera-7.53"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.securityfocus.com/bid/10517');
script_set_attribute(attribute: 'see_also', value: 'http://secunia.com/advisories/11978/');
script_set_attribute(attribute: 'see_also', value: 'http://secunia.com/advisories/12028/');
script_set_attribute(attribute: 'see_also', value: 'http://www.opera.com/linux/changelogs/753/');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200407-15.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200407-15] Opera: Multiple spoofing vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Opera: Multiple spoofing vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-client/opera", unaffected: make_list("ge 7.53"), vulnerable: make_list("le 7.52")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
