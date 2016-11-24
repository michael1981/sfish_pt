# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200901-10.xml
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
 script_id(35379);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200901-10");
 script_cve_id("CVE-2008-4989");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200901-10 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200901-10
(GnuTLS: Certificate validation error)


    Martin von Gagern reported that the _gnutls_x509_verify_certificate()
    function in lib/x509/verify.c trusts certificate chains in which the
    last certificate is an arbitrary trusted, self-signed certificate.
  
Impact

    A remote attacker could exploit this vulnerability and spoof arbitrary
    names to conduct Man-In-The-Middle attacks and intercept sensitive
    information.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All GnuTLS users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-libs/gnutls-2.4.1-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4989');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200901-10.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200901-10] GnuTLS: Certificate validation error');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'GnuTLS: Certificate validation error');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-libs/gnutls", unaffected: make_list("ge 2.4.1-r2"), vulnerable: make_list("lt 2.4.1-r2")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
