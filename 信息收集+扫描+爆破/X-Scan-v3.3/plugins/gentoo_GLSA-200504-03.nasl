# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200504-03.xml
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
 script_id(17977);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200504-03");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200504-03 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200504-03
(Dnsmasq: Poisoning and Denial of Service vulnerabilities)


    Dnsmasq does not properly detect that DNS replies received do not
    correspond to any DNS query that was sent. Rob Holland of the Gentoo
    Linux Security Audit team also discovered two off-by-one buffer
    overflows that could crash DHCP lease files parsing.
  
Impact

    A remote attacker could send malicious answers to insert arbitrary
    DNS data into the Dnsmasq cache. These attacks would in turn help an
    attacker to perform man-in-the-middle and site impersonation attacks.
    The buffer overflows might allow an attacker on the local network to
    crash Dnsmasq upon restart.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Dnsmasq users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-dns/dnsmasq-2.22"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Low');
script_set_attribute(attribute: 'see_also', value: 'http://www.thekelleys.org.uk/dnsmasq/CHANGELOG');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200504-03.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200504-03] Dnsmasq: Poisoning and Denial of Service vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Dnsmasq: Poisoning and Denial of Service vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-dns/dnsmasq", unaffected: make_list("ge 2.22"), vulnerable: make_list("lt 2.22")
)) { security_note(0); exit(0); }
exit(0, "Host is not affected");
