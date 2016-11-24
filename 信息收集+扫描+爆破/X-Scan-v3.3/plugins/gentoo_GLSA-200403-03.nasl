# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200403-03.xml
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
 script_id(14454);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200403-03");
 script_cve_id("CVE-2004-0079", "CVE-2004-0081", "CVE-2004-0112");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200403-03 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200403-03
(Multiple OpenSSL Vulnerabilities)


    Testing performed by the OpenSSL group using the Codenomicon TLS Test
    Tool uncovered a null-pointer assignment in the do_change_cipher_spec()
    function. A remote attacker could perform a carefully crafted SSL/TLS
    handshake against a server that used the OpenSSL library in such a way
    as to cause OpenSSL to crash. Depending on the application this could
    lead to a denial of service. All versions of OpenSSL from 0.9.6c to
    0.9.6l inclusive and from 0.9.7a to 0.9.7c inclusive are affected by
    this issue.
    A flaw has been discovered in SSL/TLS handshaking code when using
    Kerberos ciphersuites. A remote attacker could perform a carefully
    crafted SSL/TLS handshake against a server configured to use Kerberos
    ciphersuites in such a way as to cause OpenSSL to crash. Most
    applications have no ability to use Kerberos cipher suites and will
    therefore be unaffected. Versions 0.9.7a, 0.9.7b, and 0.9.7c of OpenSSL
    are affected by this issue.
    Testing performed by the OpenSSL group using the Codenomicon TLS Test
    Tool uncovered a bug in older versions of OpenSSL 0.9.6 that can lead
    to a Denial of Service attack (infinite loop). This issue was traced to
    a fix that was added to OpenSSL 0.9.6d some time ago. This issue will
    affect vendors that ship older versions of OpenSSL with backported
    security patches.
  
Impact

    Although there are no public exploits known for bug, users are
    recommended to upgrade to ensure the security of their infrastructure.
  
Workaround

    There is no immediate workaround; a software upgrade is required. The
    vulnerable function in the code has been rewritten.
  
');
script_set_attribute(attribute:'solution', value: '
    All users are recommened to upgrade openssl to either 0.9.7d or 0.9.6m:
    # emerge sync
    # emerge -pv ">=dev-libs/openssl-0.9.7d"
    # emerge ">=dev-libs/openssl-0.9.7d"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0079');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0081');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0112');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200403-03.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200403-03] Multiple OpenSSL Vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Multiple OpenSSL Vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-libs/openssl", unaffected: make_list("ge 0.9.7d", "eq 0.9.6m"), vulnerable: make_list("le 0.9.7c")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
