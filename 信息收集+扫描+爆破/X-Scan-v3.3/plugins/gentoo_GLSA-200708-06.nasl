# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200708-06.xml
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
 script_id(25871);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200708-06");
 script_cve_id("CVE-2007-3377", "CVE-2007-3409");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200708-06 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200708-06
(Net::DNS: Multiple vulnerabilities)


    hjp discovered an error when handling DNS query IDs which make them
    partially predictable. Steffen Ullrich discovered an error in the
    dn_expand() function which could lead to an endless loop.
  
Impact

    A remote attacker could send a specially crafted DNS request to the
    server which could result in a Denial of Service with an infinite
    recursion, or perform a cache poisoning attack.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Net::DNS users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-perl/Net-DNS-0.60"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3377');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3409');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200708-06.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200708-06] Net::DNS: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Net::DNS: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-perl/Net-DNS", unaffected: make_list("ge 0.60"), vulnerable: make_list("lt 0.60")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
