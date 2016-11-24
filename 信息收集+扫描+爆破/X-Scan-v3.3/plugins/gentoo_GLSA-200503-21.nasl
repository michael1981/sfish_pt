# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200503-21.xml
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
 script_id(17353);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200503-21");
 script_cve_id("CVE-2005-0706");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200503-21 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200503-21
(Grip: CDDB response overflow)


    Joseph VanAndel has discovered a buffer overflow in Grip when
    processing large CDDB results.
  
Impact

    A malicious CDDB server could cause Grip to crash by returning
    more then 16 matches, potentially allowing the execution of arbitrary
    code with the privileges of the user running the application.
  
Workaround

    Disable automatic CDDB queries, but we highly encourage users to
    upgrade to 3.3.0.
  
');
script_set_attribute(attribute:'solution', value: '
    All Grip users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-sound/grip-3.3.0"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0706');
script_set_attribute(attribute: 'see_also', value: 'http://sourceforge.net/tracker/?group_id=3714&atid=103714&func=detail&aid=834724');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200503-21.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200503-21] Grip: CDDB response overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Grip: CDDB response overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-sound/grip", unaffected: make_list("ge 3.3.0"), vulnerable: make_list("lt 3.3.0")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
