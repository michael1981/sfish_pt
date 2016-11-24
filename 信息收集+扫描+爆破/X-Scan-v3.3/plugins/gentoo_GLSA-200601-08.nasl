# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200601-08.xml
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
 script_id(20418);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200601-08");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200601-08 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200601-08
(Blender: Heap-based buffer overflow)


    Damian Put has reported a flaw due to an integer overflow in the
    "get_bhead()" function, leading to a heap overflow when processing
    malformed ".blend" files.
  
Impact

    A remote attacker could entice a user into opening a specially
    crafted ".blend" file, resulting in the execution of arbitrary code
    with the permissions of the user running Blender.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Blender users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-gfx/blender-2.40"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-4470');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200601-08.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200601-08] Blender: Heap-based buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Blender: Heap-based buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-gfx/blender", unaffected: make_list("ge 2.40"), vulnerable: make_list("lt 2.40")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
