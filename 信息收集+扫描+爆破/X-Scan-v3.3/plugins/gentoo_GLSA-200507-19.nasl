# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200507-19.xml
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
 script_id(19281);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200507-19");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200507-19 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200507-19
(zlib: Buffer overflow)


    zlib improperly handles invalid data streams which could lead to a
    buffer overflow.
  
Impact

    By creating a specially crafted compressed data stream, attackers
    can overwrite data structures for applications that use zlib, resulting
    in arbitrary code execution or a Denial of Service.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All zlib users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=sys-libs/zlib-1.2.3"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_set_attribute(attribute: 'see_also', value: 'http://archives.neohapsis.com/archives/fulldisclosure/2005-07/0489.html');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-1849');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200507-19.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200507-19] zlib: Buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'zlib: Buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "sys-libs/zlib", unaffected: make_list("ge 1.2.3"), vulnerable: make_list("lt 1.2.3")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
