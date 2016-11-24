# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200509-18.xml
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
 script_id(19817);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200509-18");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200509-18 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200509-18
(Qt: Buffer overflow in the included zlib library)


    Qt links to a bundled vulnerable version of zlib when emerged with the
    zlib USE-flag disabled. This may lead to a buffer overflow.
  
Impact

    By creating a specially crafted compressed data stream, attackers can
    overwrite data structures for applications that use Qt, resulting in a
    Denial of Service or potentially arbitrary code execution.
  
Workaround

    Emerge Qt with the zlib USE-flag enabled.
  
');
script_set_attribute(attribute:'solution', value: '
    All Qt users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=x11-libs/qt-3.3.4-r8"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200507-05.xml');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200507-19.xml');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-1849');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-2096');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200509-18.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200509-18] Qt: Buffer overflow in the included zlib library');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Qt: Buffer overflow in the included zlib library');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "x11-libs/qt", unaffected: make_list("ge 3.3.4-r8"), vulnerable: make_list("lt 3.3.4-r8")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
