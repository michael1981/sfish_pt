# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200812-19.xml
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
 script_id(35244);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200812-19");
 script_cve_id("CVE-2008-3337", "CVE-2008-5277");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200812-19 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200812-19
(PowerDNS: Multiple vulnerabilities)


    Daniel Drown reported an error when receiving a HINFO CH query
    (CVE-2008-5277). Brian J. Dowling of Simplicity Communications
    discovered a previously unknown security implication of the PowerDNS
    behavior to not respond to certain queries it considers malformed
    (CVE-2008-3337).
  
Impact

    A remote attacker could send specially crafted queries to cause a
    Denial of Service. The second vulnerability in itself does not pose a
    security risk to PowerDNS Nameserver. However, not answering a query
    for an invalid DNS record within a valid domain allows for a larger
    spoofing window on third-party nameservers for domains being hosted by
    PowerDNS Nameserver itself.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All PowerDNS users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-dns/pdns-2.9.21.2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3337');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5277');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200812-19.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200812-19] PowerDNS: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PowerDNS: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-dns/pdns", unaffected: make_list("ge 2.9.21.2"), vulnerable: make_list("lt 2.9.21.2")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
