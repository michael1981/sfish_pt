# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200507-20.xml
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
 script_id(19282);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200507-20");
 script_cve_id("CVE-2005-2317");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200507-20 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200507-20
(Shorewall: Security policy bypass)


    Shorewall fails to enforce security policies if configured with
    "MACLIST_DISPOSITION" set to "ACCEPT" or "MACLIST_TTL" set to a value
    greater or equal to 0.
  
Impact

    A client authenticated by MAC address filtering could bypass all
    security policies, possibly allowing him to gain access to restricted
    services. The default installation has MACLIST_DISPOSITION=REJECT and
    MACLIST_TTL=(blank) (equivalent to 0). This can be checked by looking
    at the settings in /etc/shorewall/shorewall.conf
  
Workaround

    Set "MACLIST_TTL" to "0" and "MACLIST_DISPOSITION" to "REJECT" in the
    Shorewall configuration file (usually /etc/shorewall/shorewall.conf).
  
');
script_set_attribute(attribute:'solution', value: '
    All Shorewall users should upgrade to the latest available version:
    # emerge --sync
    # emerge --ask --oneshot --verbose net-firewall/shorewall
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-2317');
script_set_attribute(attribute: 'see_also', value: 'http://www.shorewall.net/News.htm#20050717');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200507-20.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200507-20] Shorewall: Security policy bypass');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Shorewall: Security policy bypass');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-firewall/shorewall", unaffected: make_list("ge 2.4.2"), vulnerable: make_list("le 2.4.1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
