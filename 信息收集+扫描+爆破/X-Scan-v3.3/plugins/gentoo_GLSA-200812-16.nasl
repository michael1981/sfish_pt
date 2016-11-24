# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200812-16.xml
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
 script_id(35108);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200812-16");
 script_cve_id("CVE-2008-4577", "CVE-2008-4578", "CVE-2008-4870", "CVE-2008-4907");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200812-16 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200812-16
(Dovecot: Multiple vulnerabilities)


    Several vulnerabilities were found in Dovecot:
    The "k"
    right in the acl_plugin does not work as expected (CVE-2008-4577,
    CVE-2008-4578)
    The dovecot.conf is world-readable, providing
    improper protection for the ssl_key_password setting
    (CVE-2008-4870)
    A permanent Denial of Service with broken mail
    headers is possible (CVE-2008-4907)
  
Impact

    These vulnerabilities might allow a remote attacker to cause a Denial
    of Service, to circumvent security restrictions or allow local
    attackers to disclose the passphrase of the SSL private key.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Dovecot users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-mail/dovecot-1.1.7-r1"
    Users should be aware that dovecot.conf will still be world-readable
    after the update. If employing ssl_key_password, it should not be used
    in dovecot.conf but in a separate file which should be included with
    "include_try".
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4577');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4578');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4870');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4907');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200812-16.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200812-16] Dovecot: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Dovecot: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-mail/dovecot", unaffected: make_list("ge 1.1.7-r1"), vulnerable: make_list("lt 1.1.7-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
