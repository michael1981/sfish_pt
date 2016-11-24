# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200606-23.xml
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
 script_id(21743);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200606-23");
 script_cve_id("CVE-2006-2449");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200606-23 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200606-23
(KDM: Symlink vulnerability)


    Ludwig Nussel discovered that KDM could be tricked into allowing users
    to read files that would otherwise not be readable.
  
Impact

    A local attacker could exploit this issue to obtain potentially
    sensitive information that is usually not accessable to the local user
    such as shadow files or other user\'s files. The default Gentoo user
    running KDM is root and, as a result, the local attacker can read any
    file.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All kdebase users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose kde-base/kdebase
    All KDE split ebuild users should upgrade to the latest KDM version:
    # emerge --sync
    # emerge --ask --oneshot --verbose kde-base/kdm
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:H/Au:N/C:C/I:N/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://www.kde.org/info/security/advisory-20060614-1.txt');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2449');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200606-23.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200606-23] KDM: Symlink vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'KDM: Symlink vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "kde-base/kdm", unaffected: make_list("ge 3.5.2-r1", "rge 3.4.3-r2"), vulnerable: make_list("lt 3.5.2-r1")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "kde-base/kdebase", unaffected: make_list("ge 3.5.2-r2", "rge 3.4.3-r2"), vulnerable: make_list("lt 3.5.2-r2")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
