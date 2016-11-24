# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200507-23.xml
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
 script_id(19325);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200507-23");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200507-23 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200507-23
(Kopete: Vulnerability in included Gadu library)


    Kopete contains an internal copy of libgadu and is therefore
    subject to several input validation vulnerabilities in libgadu.
  
Impact

    A remote attacker could exploit this vulnerability to execute
    arbitrary code or crash Kopete.
  
Workaround

    Delete all Gadu Gadu contacts.
  
');
script_set_attribute(attribute:'solution', value: '
    All Kopete users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose kde-base/kdenetwork
    All KDE Split Ebuild Kopete users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=kde-base/kopete-3.4.1-r1"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_set_attribute(attribute: 'see_also', value: 'http://www.kde.org/info/security/advisory-20050721-1.txt');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-1852');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200507-23.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200507-23] Kopete: Vulnerability in included Gadu library');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Kopete: Vulnerability in included Gadu library');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "kde-base/kdenetwork", unaffected: make_list("ge 3.4.1-r1", "rge 3.3.2-r2"), vulnerable: make_list("lt 3.4.1-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "kde-base/kopete", unaffected: make_list("ge 3.4.1-r1"), vulnerable: make_list("lt 3.4.1-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
