# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200502-15.xml
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
 script_id(16452);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200502-15");
 script_cve_id("CVE-2005-0428");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200502-15 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200502-15
(PowerDNS: Denial of Service vulnerability)


    A vulnerability has been reported in the DNSPacket::expand method of
    dnspacket.cc.
  
Impact

    An attacker could cause a temporary Denial of Service by sending a
    random stream of bytes to the PowerDNS Daemon.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All PowerDNS users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-dns/pdns-2.9.17"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://doc.powerdns.com/changelog.html#CHANGELOG-2-9-17');
script_set_attribute(attribute: 'see_also', value: 'http://ds9a.nl/cgi-bin/cvstrac/pdns/tktview?tn=21');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0428');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200502-15.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200502-15] PowerDNS: Denial of Service vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PowerDNS: Denial of Service vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-dns/pdns", unaffected: make_list("ge 2.9.17"), vulnerable: make_list("lt 2.9.17")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
