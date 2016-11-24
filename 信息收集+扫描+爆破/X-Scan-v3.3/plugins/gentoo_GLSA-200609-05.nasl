# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200609-05.xml
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
 script_id(22327);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200609-05");
 script_cve_id("CVE-2006-4339");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200609-05 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200609-05
(OpenSSL, AMD64 x86 emulation base libraries: RSA signature forgery)


    Daniel Bleichenbacher discovered that it might be possible to forge
    signatures signed by RSA keys with the exponent of 3.
  
Impact

    Since several CAs are using an exponent of 3 it might be possible for
    an attacker to create a key with a false CA signature.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All OpenSSL users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-libs/openssl-0.9.7k"
    All AMD64 x86 emulation base libraries users should upgrade to the
    latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-emulation/emul-linux-x86-baselibs-2.5.2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4339');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200609-05.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200609-05] OpenSSL, AMD64 x86 emulation base libraries: RSA signature forgery');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'OpenSSL, AMD64 x86 emulation base libraries: RSA signature forgery');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-libs/openssl", unaffected: make_list("ge 0.9.7k"), vulnerable: make_list("lt 0.9.7k")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "app-emulation/emul-linux-x86-baselibs", arch: "amd64", unaffected: make_list("ge 2.5.2"), vulnerable: make_list("lt 2.5.2")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
