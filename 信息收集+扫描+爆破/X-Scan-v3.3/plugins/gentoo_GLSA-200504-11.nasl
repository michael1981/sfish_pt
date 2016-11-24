# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200504-11.xml
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
 script_id(18044);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200504-11");
 script_cve_id("CVE-2005-1108", "CVE-2005-1109");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200504-11 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200504-11
(JunkBuster: Multiple vulnerabilities)


    James Ranson reported a vulnerability when JunkBuster is configured to
    run in single-threaded mode, an attacker can modify the referrer
    setting by getting a victim to request a specially crafted URL
    (CAN-2005-1108). Tavis Ormandy of the Gentoo Linux Security Audit Team
    identified a heap corruption issue in the filtering of URLs
    (CAN-2005-1109).
  
Impact

    If JunkBuster has been configured to run in single-threaded mode, an
    attacker can disable or modify the filtering of Referrer: HTTP headers,
    potentially compromising the privacy of users. The heap corruption
    vulnerability could crash or disrupt the operation of the proxy,
    potentially executing arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All JunkBuster users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-proxy/junkbuster-2.0.2-r3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-1108');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-1109');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200504-11.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200504-11] JunkBuster: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'JunkBuster: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-proxy/junkbuster", unaffected: make_list("ge 2.0.2-r3"), vulnerable: make_list("lt 2.0.2-r3")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
