# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200507-05.xml
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
 script_id(18634);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200507-05");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200507-05 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200507-05
(zlib: Buffer overflow)


    Tavis Ormandy of the Gentoo Linux Security Audit Team discovered a
    buffer overflow in zlib. A bounds checking operation failed to take
    invalid data into account, allowing a specifically malformed deflate
    data stream to overrun a buffer.
  
Impact

    An attacker could construct a malformed data stream, embedding it
    within network communication or an application file format, potentially
    resulting in the execution of arbitrary code when decoded by the
    application using the zlib library.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All zlib users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=sys-libs/zlib-1.2.2-r1"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-2096');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200507-05.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200507-05] zlib: Buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'zlib: Buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "sys-libs/zlib", unaffected: make_list("ge 1.2.2-r1"), vulnerable: make_list("lt 1.2.2-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
