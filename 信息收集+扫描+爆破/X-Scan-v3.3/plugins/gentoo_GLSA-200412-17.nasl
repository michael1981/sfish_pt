# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200412-17.xml
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
 script_id(16004);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200412-17");
 script_cve_id("CVE-2004-0803", "CVE-2004-0804", "CVE-2004-0886");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200412-17 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200412-17
(kfax: Multiple overflows in the included TIFF library)


    Than Ngo discovered that kfax contains a private copy of the TIFF
    library and is therefore subject to several known vulnerabilities (see
    References).
  
Impact

    A remote attacker could entice a user to view a carefully-crafted TIFF
    image file with kfax, which would potentially lead to execution of
    arbitrary code with the rights of the user running kfax.
  
Workaround

    The KDE Team recommends to remove the kfax binary as well as the
    kfaxpart.la KPart:
    rm /usr/kde/3.*/lib/kde3/kfaxpart.la
    rm /usr/kde/3.*/bin/kfax
    Note: This will render the kfax functionality useless, if kfax
    functionality is needed you should upgrade to the KDE 3.3.2 which is
    not stable at the time of this writing.
    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All kfax users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=kde-base/kdegraphics-3.3.2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.kde.org/info/security/advisory-20041209-2.txt');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200410-11.xml');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0803');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0804');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0886');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200412-17.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200412-17] kfax: Multiple overflows in the included TIFF library');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'kfax: Multiple overflows in the included TIFF library');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "kde-base/kdegraphics", unaffected: make_list("ge 3.3.2"), vulnerable: make_list("lt 3.3.2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
