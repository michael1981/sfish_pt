# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200609-11.xml
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
 script_id(22356);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200609-11");
 script_cve_id("CVE-2006-4095", "CVE-2006-4096");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200609-11 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200609-11
(BIND: Denial of Service)


    Queries for SIG records will cause an assertion error if more than one
    SIG RRset is returned. Additionally, an INSIST failure can be triggered
    by sending multiple recursive queries if the response to the query
    arrives after all the clients looking for the response have left the
    recursion queue.
  
Impact

    An attacker having access to a recursive server can crash the server by
    querying the SIG records where there are multiple SIG RRsets, or by
    sending many recursive queries in a short time. The exposure can be
    lowered by restricting the clients that can ask for recursion. An
    attacker can also crash an authoritative server serving a DNSSEC zone
    in which there are multiple SIG RRsets.
  
Workaround

    There are no known workarounds at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All BIND 9.3 users should update to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-dns/bind-9.3.2-r4"
    All BIND 9.2 users should update to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-dns/bind-9.2.6-r4"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4095');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4096');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200609-11.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200609-11] BIND: Denial of Service');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'BIND: Denial of Service');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-dns/bind", unaffected: make_list("ge 9.3.2-r4", "rge 9.2.6-r4"), vulnerable: make_list("lt 9.3.2-r4")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
