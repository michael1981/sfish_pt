# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200905-04.xml
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
 script_id(38885);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200905-04");
 script_cve_id("CVE-2009-1415", "CVE-2009-1416", "CVE-2009-1417");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200905-04 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200905-04
(GnuTLS: Multiple vulnerabilities)


    The following vulnerabilities were found in GnuTLS:
    Miroslav Kratochvil reported that lib/pk-libgcrypt.c does not
    properly handle corrupt DSA signatures, possibly leading to a
    double-free vulnerability (CVE-2009-1415).
    Simon Josefsson
    reported that GnuTLS generates RSA keys stored in DSA structures when
    creating a DSA key (CVE-2009-1416).
    Romain Francoise reported
    that the _gnutls_x509_verify_certificate() function in
    lib/x509/verify.c does not perform time checks, resulting in the
    "gnutls-cli" program accepting X.509 certificates with validity times
    in the past or future (CVE-2009-1417).
  
Impact

    A remote attacker could entice a user or automated system to process a
    specially crafted DSA certificate, possibly resulting in a Denial of
    Service condition. NOTE: This issue might have other unspecified impact
    including the execution of arbitrary code. Furthermore, a remote
    attacker could spoof signatures on certificates and the "gnutls-cli"
    application can be tricked into accepting an invalid certificate.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All GnuTLS users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-libs/gnutls-2.6.6"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1415');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1416');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1417');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200905-04.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200905-04] GnuTLS: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'GnuTLS: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-libs/gnutls", unaffected: make_list("ge 2.6.6"), vulnerable: make_list("lt 2.6.6")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
