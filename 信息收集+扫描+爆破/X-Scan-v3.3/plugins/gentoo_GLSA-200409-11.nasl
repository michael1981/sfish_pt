# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-11.xml
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
 script_id(14675);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200409-11");
 script_cve_id("CVE-2004-0850");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200409-11 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200409-11
(star: Suid root vulnerability)


    A suid root vulnerability exists in versions of star that are
    configured to use ssh for remote tape access.
  
Impact

    Attackers with local user level access could potentially gain root
    level access.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All star users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=app-arch/star-1.5_alpha46"
    # emerge ">=app-arch/star-1.5_alpha46"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'https://lists.berlios.de/pipermail/star-users/2004-August/000239.html');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0850');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200409-11.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200409-11] star: Suid root vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'star: Suid root vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-arch/star", unaffected: make_list("ge 1.5_alpha46"), vulnerable: make_list("lt 1.5_alpha46")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
