# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200702-06.xml
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
 script_id(24367);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200702-06");
 script_cve_id("CVE-2007-0493", "CVE-2007-0494");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200702-06 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200702-06
(BIND: Denial of Service)


    An unspecified improper usage of an already freed context has been
    reported. Additionally, an assertion error could be triggered in the
    DNSSEC validation of some responses to type ANY queries with multiple
    RRsets.
  
Impact

    A remote attacker could crash the server through unspecified vectors
    or, if DNSSEC validation is enabled, by sending certain crafted ANY
    queries.
  
Workaround

    There is no known workaround at this time for the first issue. The
    DNSSEC validation Denial of Service can be prevented by disabling
    DNSSEC validation until the upgrade to a fixed version. Note that
    DNSSEC validation is disabled on a default configuration.
  
');
script_set_attribute(attribute:'solution', value: '
    All ISC BIND 9.3 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-dns/bind-9.3.4"
    All ISC BIND 9.2 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-dns/bind-9.2.8"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0493');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0494');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200702-06.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200702-06] BIND: Denial of Service');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'BIND: Denial of Service');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-dns/bind", unaffected: make_list("ge 9.3.4", "rge 9.2.8"), vulnerable: make_list("lt 9.3.4")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
