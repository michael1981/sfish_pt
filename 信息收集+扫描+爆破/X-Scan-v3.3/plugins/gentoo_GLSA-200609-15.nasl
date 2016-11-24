# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200609-15.xml
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
 script_id(22459);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200609-15");
 script_cve_id("CVE-2006-4790");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200609-15 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200609-15
(GnuTLS: RSA Signature Forgery)


    verify.c fails to properly handle excess data in
    digestAlgorithm.parameters field while generating a hash when using an
    RSA key with exponent 3. RSA keys that use exponent 3 are commonplace.
  
Impact

    Remote attackers could forge PKCS #1 v1.5 signatures that are signed
    with an RSA key, preventing GnuTLS from correctly verifying X.509 and
    other certificates that use PKCS.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All GnuTLS users should update both packages:
    # emerge --sync
    # emerge --update --ask --verbose ">=net-libs/gnutls-1.4.4"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4790');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200609-15.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200609-15] GnuTLS: RSA Signature Forgery');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'GnuTLS: RSA Signature Forgery');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-libs/gnutls", unaffected: make_list("ge 1.4.4"), vulnerable: make_list("lt 1.4.4")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
