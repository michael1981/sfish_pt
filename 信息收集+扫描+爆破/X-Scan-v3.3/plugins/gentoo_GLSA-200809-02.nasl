# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200809-02.xml
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
 script_id(34091);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200809-02");
 script_cve_id("CVE-2008-3350", "CVE-2008-1447");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200809-02 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200809-02
(dnsmasq: Denial of Service and DNS spoofing)


    Dan Kaminsky of IOActive reported that dnsmasq does not randomize UDP
    source ports when forwarding DNS queries to a recursing DNS server
    (CVE-2008-1447).
    Carlos Carvalho reported that dnsmasq in the 2.43 version does not
    properly handle clients sending inform or renewal queries for unknown
    DHCP leases, leading to a crash (CVE-2008-3350).
  
Impact

    A remote attacker could send spoofed DNS response traffic to dnsmasq,
    possibly involving generating queries via multiple vectors, and spoof
    DNS replies, which could e.g. lead to the redirection of web or mail
    traffic to malicious sites. Furthermore, an attacker could generate
    invalid DHCP traffic and cause a Denial of Service.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All dnsmasq users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-dns/dnsmasq-2.45"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3350');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1447');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200809-02.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200809-02] dnsmasq: Denial of Service and DNS spoofing');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'dnsmasq: Denial of Service and DNS spoofing');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-dns/dnsmasq", unaffected: make_list("ge 2.45"), vulnerable: make_list("lt 2.45")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
