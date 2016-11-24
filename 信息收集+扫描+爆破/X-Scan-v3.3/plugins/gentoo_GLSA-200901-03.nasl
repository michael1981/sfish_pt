# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200901-03.xml
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
 script_id(35347);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200901-03");
 script_cve_id("CVE-2008-1447", "CVE-2008-4194");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200901-03 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200901-03
(pdnsd: Denial of Service and cache poisoning)


    Two issues have been reported in pdnsd:
    The p_exec_query() function in src/dns_query.c does not properly handle
    many entries in the answer section of a DNS reply, related to a
    "dangling pointer bug" (CVE-2008-4194).
    The default value for query_port_start was set to 0, disabling UDP
    source port randomization for outgoing queries (CVE-2008-1447).
  
Impact

    An attacker could exploit the second weakness to poison the cache of
    pdnsd and thus spoof DNS traffic, which could e.g. lead to the
    redirection of web or mail traffic to malicious sites. The first issue
    can be exploited by enticing pdnsd to send a query to a malicious DNS
    server, or using the port randomization weakness, and might lead to a
    Denial of Service.
  
Workaround

    Port randomization can be enabled by setting the "query_port_start"
    option to 1024 which would resolve the CVE-2008-1447 issue.
  
');
script_set_attribute(attribute:'solution', value: '
    All pdnsd users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-dns/pdnsd-1.2.7"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1447');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4194');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200901-03.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200901-03] pdnsd: Denial of Service and cache poisoning');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'pdnsd: Denial of Service and cache poisoning');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-dns/pdnsd", unaffected: make_list("ge 1.2.7"), vulnerable: make_list("lt 1.2.7")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
