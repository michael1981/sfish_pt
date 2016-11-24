# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200612-11.xml
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
 script_id(23863);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200612-11");
 script_cve_id("CVE-2006-2937", "CVE-2006-2940", "CVE-2006-3738", "CVE-2006-4343");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200612-11 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200612-11
(AMD64 x86 emulation base libraries: OpenSSL multiple vulnerabilities)


    Tavis Ormandy and Will Drewry, both of the Google Security Team,
    discovered that the SSL_get_shared_ciphers() function contains a buffer
    overflow vulnerability, and that the SSLv2 client code contains a flaw
    leading to a crash. Additionally, Dr. Stephen N. Henson found that the
    ASN.1 handler contains two Denial of Service vulnerabilities: while
    parsing an invalid ASN.1 structure and while handling certain types of
    public key.
  
Impact

    An attacker could trigger the buffer overflow by sending a malicious
    suite of ciphers to an application using the vulnerable function, and
    thus execute arbitrary code with the rights of the user running the
    application. An attacker could also consume CPU and/or memory by
    exploiting the Denial of Service vulnerabilities. Finally, a malicious
    server could crash a SSLv2 client through the SSLv2 vulnerability.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All AMD64 x86 emulation base libraries users should upgrade to the
    latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-emulation/emul-linux-x86-baselibs-2.5.5"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2937');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2940');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3738');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4343');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200612-11.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200612-11] AMD64 x86 emulation base libraries: OpenSSL multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'AMD64 x86 emulation base libraries: OpenSSL multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-emulation/emul-linux-x86-baselibs", arch: "amd64", unaffected: make_list("ge 2.5.5"), vulnerable: make_list("lt 2.5.5")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
