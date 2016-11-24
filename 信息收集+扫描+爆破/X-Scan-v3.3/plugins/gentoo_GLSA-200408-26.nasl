# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200408-26.xml
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
 script_id(14582);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200408-26");
 script_cve_id("CVE-2004-0797");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200408-26 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200408-26
(zlib: Denial of service vulnerability)


    zlib contains a bug in the handling of errors in the "inflate()" and
    "inflateBack()" functions.
  
Impact

    An attacker could exploit this vulnerability to launch a Denial of
    Service attack on any application using the zlib library.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version of zlib.
  
');
script_set_attribute(attribute:'solution', value: '
    All zlib users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=sys-libs/zlib-1.2.1-r3"
    # emerge ">=sys-libs/zlib-1.2.1-r3"
    You should also run revdep-rebuild to rebuild any packages that depend
    on older versions of zlib :
    # revdep-rebuild
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.openpkg.org/security/OpenPKG-SA-2004.038-zlib.html');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0797');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200408-26.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200408-26] zlib: Denial of service vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'zlib: Denial of service vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "sys-libs/zlib", unaffected: make_list("ge 1.2.1-r3"), vulnerable: make_list("le 1.2.1-r2")
)) { security_note(0); exit(0); }
exit(0, "Host is not affected");
