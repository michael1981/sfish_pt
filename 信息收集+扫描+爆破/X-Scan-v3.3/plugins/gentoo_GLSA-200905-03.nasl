# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200905-03.xml
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
 script_id(38884);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200905-03");
 script_cve_id("CVE-2009-1574", "CVE-2009-1632");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200905-03 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200905-03
(IPSec Tools: Denial of Service)


    The following vulnerabilities have been found in the racoon daemon as
    shipped with IPSec Tools:
    Neil Kettle reported that
    racoon/isakmp_frag.c is prone to a null-pointer dereference
    (CVE-2009-1574).
    Multiple memory leaks exist in (1) the
    eay_check_x509sign() function in racoon/crypto_openssl.c and (2)
    racoon/nattraversal.c (CVE-2009-1632).
  
Impact

    A remote attacker could send specially crafted fragmented ISAKMP
    packets without a payload or exploit vectors related to X.509
    certificate authentication and NAT traversal, possibly resulting in a
    crash of the racoon daemon.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All IPSec Tools users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-firewall/ipsec-tools-0.7.2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1574');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1632');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200905-03.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200905-03] IPSec Tools: Denial of Service');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'IPSec Tools: Denial of Service');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-firewall/ipsec-tools", unaffected: make_list("ge 0.7.2"), vulnerable: make_list("lt 0.7.2")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
