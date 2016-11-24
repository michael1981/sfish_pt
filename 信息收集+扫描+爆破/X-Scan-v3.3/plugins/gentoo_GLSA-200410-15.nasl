# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200410-15.xml
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
 script_id(15512);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200410-15");
 script_cve_id("CVE-2004-0918");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200410-15 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200410-15
(Squid: Remote DoS vulnerability)


    A parsing error exists in the SNMP module of Squid where a
    specially-crafted UDP packet can potentially cause the server to
    restart, closing all current connections. This vulnerability only
    exists in versions of Squid compiled with the \'snmp\' USE flag.
  
Impact

    An attacker can repeatedly send these malicious UDP packets to the
    Squid server, leading to a denial of service.
  
Workaround

    Disable SNMP support or filter the port that has SNMP processing
    (default is 3401) to allow only SNMP data from trusted hosts.
    To disable SNMP support put the entry snmp_port 0 in the squid.conf
    configuration file.
    To allow only the local interface to process SNMP, add the entry
    "snmp_incoming_address 127.0.0.1" in the squid.conf configuration file.
  
');
script_set_attribute(attribute:'solution', value: '
    All Squid users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=net-proxy/squid-2.5.7"
    # emerge ">=net-proxy/squid-2.5.7"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.idefense.com/application/poi/display?id=152&type=vulnerabilities&flashstatus=true');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0918');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200410-15.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200410-15] Squid: Remote DoS vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Squid: Remote DoS vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-proxy/squid", unaffected: make_list("ge 2.5.7"), vulnerable: make_list("lt 2.5.7")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
