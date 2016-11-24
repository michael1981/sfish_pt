# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200904-11.xml
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
 script_id(36139);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200904-11");
 script_cve_id("CVE-2008-5397", "CVE-2008-5398", "CVE-2009-0414", "CVE-2009-0936", "CVE-2009-0937", "CVE-2009-0938", "CVE-2009-0939");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200904-11 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200904-11
(Tor: Multiple vulnerabilities)


    Theo de Raadt reported that the application does not properly drop
    privileges to the primary groups of the user specified via the "User"
    configuration option (CVE-2008-5397).
    rovv reported that the "ClientDNSRejectInternalAddresses" configuration
    option is not always enforced (CVE-2008-5398).
    Ilja van Sprundel reported a heap-corruption vulnerability that might
    be remotely triggerable on some platforms (CVE-2009-0414).
    It has been reported that incomplete IPv4 addresses are treated as
    valid, violating the specification (CVE-2009-0939).
    Three unspecified vulnerabilities have also been reported
    (CVE-2009-0936, CVE-2009-0937, CVE-2009-0938).
  
Impact

    A local attacker could escalate privileges by leveraging unintended
    supplementary group memberships of the Tor process. A remote attacker
    could exploit these vulnerabilities to cause a heap corruption with
    unknown impact and attack vectors, to cause a Denial of Service via CPU
    consuption or daemon crash, and to weaken anonymity provided by the
    service.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Tor users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/tor-0.2.0.34"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5397');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5398');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0414');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0936');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0937');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0938');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0939');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200904-11.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200904-11] Tor: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Tor: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/tor", unaffected: make_list("ge 0.2.0.34"), vulnerable: make_list("lt 0.2.0.34")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
