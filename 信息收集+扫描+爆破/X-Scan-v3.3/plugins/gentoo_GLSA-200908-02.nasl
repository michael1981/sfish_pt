# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200908-02.xml
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
 script_id(40463);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200908-02");
 script_cve_id("CVE-2009-0696");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200908-02 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200908-02
(BIND: Denial of Service)


    Matthias Urlichs reported that the dns_db_findrdataset() function fails
    when the prerequisite section of the dynamic update message contains a
    record of type "ANY" and where at least one RRset for this FQDN exists
    on the server.
  
Impact

    A remote unauthenticated attacker could send a specially crafted
    dynamic update message to the BIND daemon (named), leading to a Denial
    of Service (daemon crash). This vulnerability affects all primary
    (master) servers -- it is not limited to those that are configured to
    allow dynamic updates.
  
Workaround

    Configure a firewall that performs Deep Packet Inspection to prevent
    nsupdate messages from reaching named. Alternatively, expose only
    secondary (slave) servers to untrusted networks.
  
');
script_set_attribute(attribute:'solution', value: '
    All BIND users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-dns/bind-9.4.3_p3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0696');
script_set_attribute(attribute: 'see_also', value: 'https://www.isc.org/node/474');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200908-02.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200908-02] BIND: Denial of Service');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'BIND: Denial of Service');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-dns/bind", unaffected: make_list("ge 9.4.3_p3"), vulnerable: make_list("lt 9.4.3_p3")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
