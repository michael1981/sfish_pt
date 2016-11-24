# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200406-21.xml
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
 script_id(14532);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200406-21");
 script_cve_id("CVE-2004-0523");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200406-21 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200406-21
(mit-krb5: Multiple buffer overflows in krb5_aname_to_localname)


    The library function krb5_aname_to_localname() contains multiple buffer
    overflows. This is only exploitable if explicit mapping or rules-based
    mapping is enabled. These are not enabled as default.
    With explicit mapping enabled, an attacker must authenticate using a
    principal name listed in the explicit mapping list.
    With rules-based mapping enabled, an attacker must first be able to create
    arbitrary principal names either in the local realm Kerberos realm or in a
    remote realm from which the local realm\'s service are reachable by
    cross-realm authentication.
  
Impact

    An attacker could use these vulnerabilities to execute arbitrary code with
    the permissions of the user running mit-krb5, which could be the root user.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version.
  
');
script_set_attribute(attribute:'solution', value: '
    mit-krb5 users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=app-crypt/mit-krb5-1.3.3-r1"
    # emerge ">=app-crypt/mit-krb5-1.3.3-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0523');
script_set_attribute(attribute: 'see_also', value: 'http://web.mit.edu/kerberos/advisories/MITKRB5-SA-2004-001-an_to_ln.txt');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200406-21.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200406-21] mit-krb5: Multiple buffer overflows in krb5_aname_to_localname');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'mit-krb5: Multiple buffer overflows in krb5_aname_to_localname');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-crypt/mit-krb5", unaffected: make_list("ge 1.3.3-r1"), vulnerable: make_list("le 1.3.3")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
