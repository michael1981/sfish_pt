# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200712-23.xml
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
 script_id(29820);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200712-23");
 script_cve_id("CVE-2007-6111", "CVE-2007-6112", "CVE-2007-6113", "CVE-2007-6114", "CVE-2007-6115", "CVE-2007-6116", "CVE-2007-6117", "CVE-2007-6118", "CVE-2007-6119", "CVE-2007-6120", "CVE-2007-6121", "CVE-2007-6438", "CVE-2007-6439", "CVE-2007-6441", "CVE-2007-6450", "CVE-2007-6451");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200712-23 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200712-23
(Wireshark: Multiple vulnerabilities)


    Multiple buffer overflows and infinite loops were discovered in
    multiple dissector and parser components, including those for MP3 and
    NCP (CVE-2007-6111), PPP (CVE-2007-6112), DNP (CVE-2007-6113), SSL and
    iSeries (OS/400) Communication traces (CVE-2007-6114), ANSI MAP
    (CVE-2007-6115), Firebird/Interbase (CVE-2007-6116), HTTP
    (CVE-2007-6117), MEGACO (CVE-2007-6118), DCP ETSI (CVE-2007-6119),
    Bluetooth SDP (CVE-2007-6120), RPC Portmap (CVE-2007-6121), SMB
    (CVE-2007-6438), IPv6 amd USB (CVE-2007-6439), WiMAX (CVE-2007-6441),
    RPL (CVE-2007-6450), CIP (CVE-2007-6451). The vulnerabilities were
    discovered by Stefan Esser, Beyond Security, Fabiodds, Peter Leeming,
    Steve and ainsley.
  
Impact

    A remote attacker could send specially crafted packets on a network
    being monitored with Wireshark or entice a user to open a specially
    crafted file, possibly resulting in the execution of arbitrary code
    with the privileges of the user running Wireshark (which might be the
    root user), or a Denial of Service.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Wireshark users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-analyzer/wireshark-0.99.7"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6111');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6112');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6113');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6114');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6115');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6116');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6117');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6118');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6119');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6120');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6121');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6438');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6439');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6441');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6450');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6451');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200712-23.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200712-23] Wireshark: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Wireshark: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-analyzer/wireshark", unaffected: make_list("ge 0.99.7"), vulnerable: make_list("lt 0.99.7")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
