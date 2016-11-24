# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200904-09.xml
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
 script_id(36137);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200904-09");
 script_cve_id("CVE-2009-0844", "CVE-2009-0845", "CVE-2009-0846", "CVE-2009-0847");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200904-09 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200904-09
(MIT Kerberos 5: Multiple vulnerabilities)


    Multiple vulnerabilities have been reported in MIT Kerberos 5:
    A free() call on an uninitialized pointer in the ASN.1 decoder
    when decoding an invalid encoding (CVE-2009-0846).
    A buffer
    overread in the SPNEGO GSS-API application, reported by Apple Product
    Security (CVE-2009-0844).
    A NULL pointer dereference in the
    SPNEGO GSS-API application, reported by Richard Evans
    (CVE-2009-0845).
    An incorrect length check inside an ASN.1
    decoder leading to spurious malloc() failures (CVE-2009-0847).
  
Impact

    A remote unauthenticated attacker could exploit the first vulnerability
    to cause a Denial of Service or, in unlikely circumstances, execute
    arbitrary code on the host running krb5kdc or kadmind with root
    privileges and compromise the Kerberos key database. Exploitation of
    the other vulnerabilities might lead to a Denial of Service in kadmind,
    krb5kdc, or other daemons performing authorization against Kerberos
    that utilize GSS-API or an information disclosure.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All MIT Kerberos 5 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-crypt/mit-krb5-1.6.3-r6"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0844');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0845');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0846');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0847');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200904-09.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200904-09] MIT Kerberos 5: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'MIT Kerberos 5: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-crypt/mit-krb5", unaffected: make_list("ge 1.6.3-r6"), vulnerable: make_list("lt 1.6.3-r6")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
