# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200507-11.xml
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
 script_id(18686);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200507-11");
 script_cve_id("CVE-2005-1174", "CVE-2005-1175", "CVE-2005-1689");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200507-11 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200507-11
(MIT Kerberos 5: Multiple vulnerabilities)


    Daniel Wachdorf discovered that MIT Kerberos 5 could corrupt the
    heap by freeing unallocated memory when receiving a special TCP request
    (CAN-2005-1174). He also discovered that the same request could lead to
    a single-byte heap overflow (CAN-2005-1175). Magnus Hagander discovered
    that krb5_recvauth() function of MIT Kerberos 5 might try to
    double-free memory (CAN-2005-1689).
  
Impact

    Although exploitation is considered difficult, a remote attacker
    could exploit the single-byte heap overflow and the double-free
    vulnerability to execute arbitrary code, which could lead to the
    compromise of the whole Kerberos realm. A remote attacker could also
    use the heap corruption to cause a Denial of Service.
  
Workaround

    There are no known workarounds at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All MIT Kerberos 5 users should upgrade to the latest available
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-crypt/mit-krb5-1.4.1-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-1174');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-1175');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-1689');
script_set_attribute(attribute: 'see_also', value: 'http://web.mit.edu/kerberos/advisories/MITKRB5-SA-2005-002-kdc.txt');
script_set_attribute(attribute: 'see_also', value: 'http://web.mit.edu/kerberos/advisories/MITKRB5-SA-2005-003-recvauth.txt');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200507-11.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200507-11] MIT Kerberos 5: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'MIT Kerberos 5: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-crypt/mit-krb5", unaffected: make_list("ge 1.4.1-r1"), vulnerable: make_list("lt 1.4.1-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
