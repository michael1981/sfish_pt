# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-15.xml
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
 script_id(16406);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200501-15");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200501-15 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200501-15
(UnRTF: Buffer overflow)


    An unchecked strcat() in unrtf may overflow the bounds of a static
    buffer.
  
Impact

    Using a specially crafted file, possibly delivered by e-mail or
    over the web, an attacker may execute arbitrary code with the
    permissions of the user running UnRTF.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All unrtf users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/unrtf-0.19.3-r1"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://tigger.uic.edu/~jlongs2/holes/unrtf.txt');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200501-15.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200501-15] UnRTF: Buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'UnRTF: Buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-text/unrtf", unaffected: make_list("ge 0.19.3-r1"), vulnerable: make_list("lt 0.19.3-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
