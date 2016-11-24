# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200703-22.xml
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
 script_id(24888);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200703-22");
 script_cve_id("CVE-2007-0008", "CVE-2007-0009");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200703-22 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200703-22
(Mozilla Network Security Service: Remote execution of arbitrary code)


    iDefense has reported two potential buffer overflow vulnerabilities
    found by researcher "regenrecht" in the code implementing the SSLv2
    protocol.
  
Impact

    A remote attacker could send a specially crafted SSL master key to a
    server using NSS for the SSLv2 protocol, or entice a user to connect to
    a malicious server with a client-side application using NSS like one of
    the Mozilla products. This could trigger the vulnerabilities and result
    in the possible execution of arbitrary code with the rights of the
    vulnerable application.
  
Workaround

    Disable the SSLv2 protocol in the applications using NSS.
  
');
script_set_attribute(attribute:'solution', value: '
    All NSS users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-libs/nss-3.11.5"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0008');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0009');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200703-22.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200703-22] Mozilla Network Security Service: Remote execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Mozilla Network Security Service: Remote execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-libs/nss", unaffected: make_list("ge 3.11.5"), vulnerable: make_list("lt 3.11.5")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
