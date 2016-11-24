# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200708-12.xml
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
 script_id(25918);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200708-12");
 script_cve_id("CVE-2007-3389", "CVE-2007-3390", "CVE-2007-3391", "CVE-2007-3392", "CVE-2007-3393");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200708-12 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200708-12
(Wireshark: Multiple vulnerabilities)


    Wireshark doesn\'t properly handle chunked encoding in HTTP responses
    (CVE-2007-3389), iSeries capture files (CVE-2007-3390), certain types
    of DCP ETSI packets (CVE-2007-3391), and SSL or MMS packets
    (CVE-2007-3392). An off-by-one error has been discovered in the
    DHCP/BOOTP dissector when handling DHCP-over-DOCSIS packets
    (CVE-2007-3393).
  
Impact

    A remote attacker could send specially crafted packets on a network
    being monitored with Wireshark, possibly resulting in the execution of
    arbitrary code with the privileges of the user running Wireshark which
    might be the root user, or a Denial of Service.
  
Workaround

    In order to prevent root compromise, take network captures with tcpdump
    and analyze them running Wireshark as a least privileged user.
  
');
script_set_attribute(attribute:'solution', value: '
    All Wireshark users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-analyzer/wireshark-0.99.6"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3389');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3390');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3391');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3392');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3393');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200708-12.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200708-12] Wireshark: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Wireshark: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-analyzer/wireshark", unaffected: make_list("ge 0.99.6"), vulnerable: make_list("lt 0.99.6")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
