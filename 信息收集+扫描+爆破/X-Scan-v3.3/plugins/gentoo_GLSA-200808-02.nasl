# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200808-02.xml
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
 script_id(33832);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200808-02");
 script_cve_id("CVE-2008-0960", "CVE-2008-2292");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200808-02 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200808-02
(Net-SNMP: Multiple vulnerabilities)


    Wes Hardaker reported that the SNMPv3 HMAC verification relies on the
    client to specify the HMAC length (CVE-2008-0960). John Kortink
    reported a buffer overflow in the Perl bindings of Net-SNMP when
    processing the OCTETSTRING in an attribute value pair (AVP) received by
    an SNMP agent (CVE-2008-2292).
  
Impact

    An attacker could send SNMPv3 packets to an instance of snmpd providing
    a valid user name and an HMAC length value of 1, and easily conduct
    brute-force attacks to bypass SNMP authentication. An attacker could
    further entice a user to connect to a malicious SNMP agent with an SNMP
    client using the Perl bindings, possibly resulting in the execution of
    arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Net-SNMP users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-analyzer/net-snmp-5.4.1.1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0960');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2292');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200808-02.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200808-02] Net-SNMP: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Net-SNMP: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-analyzer/net-snmp", unaffected: make_list("ge 5.4.1.1"), vulnerable: make_list("lt 5.4.1.1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
