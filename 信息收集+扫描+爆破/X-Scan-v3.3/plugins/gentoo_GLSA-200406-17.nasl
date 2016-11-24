# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200406-17.xml
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
 script_id(14528);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200406-17");
 script_cve_id("CVE-2004-0155", "CVE-2004-0607");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200406-17 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200406-17
(IPsec-Tools: authentication bug in racoon)


    The KAME IKE daemon racoon is used to authenticate peers during Phase 1
    when using either preshared keys, GSS-API, or RSA signatures. When
    using RSA signatures racoon validates the X.509 certificate but not the
    RSA signature.
  
Impact

    By sending a valid and trusted X.509 certificate and any private key an
    attacker could exploit this vulnerability to perform man-in-the-middle
    attacks and initiate unauthorized connections.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version.
  
');
script_set_attribute(attribute:'solution', value: '
    All IPsec-Tools users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=net-firewall/ipsec-tools-0.3.3"
    # emerge ">=net-firewall/ipsec-tools-0.3.3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://ipsec-tools.sourceforge.net/x509sig.html');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0155');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0607');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200406-17.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200406-17] IPsec-Tools: authentication bug in racoon');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'IPsec-Tools: authentication bug in racoon');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-firewall/ipsec-tools", unaffected: make_list("ge 0.3.3"), vulnerable: make_list("lt 0.3.3")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
