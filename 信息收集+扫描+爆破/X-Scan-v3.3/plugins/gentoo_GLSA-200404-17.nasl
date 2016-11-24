# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200404-17.xml
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
 script_id(14482);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200404-17");
 script_cve_id("CVE-2004-0403");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200404-17 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200404-17
(ipsec-tools and iputils contain a remote DoS vulnerability)


    When racoon receives an ISAKMP header, it allocates memory based on the
    length of the header field. Thus, an attacker may be able to cause a Denial
    of Services by creating a header that is large enough to consume all
    available system resources.
  
Impact

    This vulnerability may allow an attacker to remotely cause a Denial of
    Service.
  
Workaround

    A workaround is not currently known for this issue. All users are advised
    to upgrade to the latest version of the affected package.
  
');
script_set_attribute(attribute:'solution', value: '
    ipsec-tools users should upgrade to version 0.2.5 or later:
    # emerge sync
    # emerge -pv ">=net-firewall/ipsec-tools-0.3.1"
    # emerge ">=net-firewall/ipsec-tools-0.3.1"
    iputils users should upgrade to version 021109-r3 or later:
    # emerge sync
    # emerge -pv ">=net-misc/iputils-021109-r3"
    # emerge ">=net-misc/iputils-021109-r3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://ipsec-tools.sourceforge.net/');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0403');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200404-17.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200404-17] ipsec-tools and iputils contain a remote DoS vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ipsec-tools and iputils contain a remote DoS vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/iputils", arch: "ppc amd64 ppc64 s390", unaffected: make_list("eq 021109-r3"), vulnerable: make_list("eq 021109-r1")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "net-firewall/ipsec-tools", arch: "amd64", unaffected: make_list("ge 0.3.1"), vulnerable: make_list("lt 0.3.1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
