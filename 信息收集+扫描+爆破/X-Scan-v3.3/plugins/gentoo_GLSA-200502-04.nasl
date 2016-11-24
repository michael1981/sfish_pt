# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200502-04.xml
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
 script_id(16441);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200502-04");
 script_cve_id("CVE-2005-0173", "CVE-2005-0174", "CVE-2005-0175", "CVE-2005-0211");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200502-04 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200502-04
(Squid: Multiple vulnerabilities)


    Squid contains several vulnerabilities:
    Buffer overflow when handling WCCP recvfrom()
    (CAN-2005-0211).
    Loose checking of HTTP headers (CAN-2005-0173 and
    CAN-2005-0174).
    Incorrect handling of LDAP login names with spaces
    (CAN-2005-0175).
  
Impact

    An attacker could exploit:
    the WCCP buffer overflow to cause Denial of Service.
    the HTTP header parsing vulnerabilities to inject arbitrary
    response data, potentially leading to content spoofing, web cache
    poisoning and other cross-site scripting or HTTP response splitting
    attacks.
    the LDAP issue to login with several variations of the same login
    name, leading to log poisoning.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Squid users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-proxy/squid-2.5.7-r5"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0173');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0174');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0175');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0211');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200502-04.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200502-04] Squid: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Squid: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-proxy/squid", unaffected: make_list("ge 2.5.7-r5"), vulnerable: make_list("lt 2.5.7-r5")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
