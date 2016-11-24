# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200503-13.xml
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
 script_id(17287);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200503-13");
 script_cve_id("CVE-2005-0686");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200503-13 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200503-13
(mlterm: Integer overflow vulnerability)


    mlterm is vulnerable to an integer overflow that can be triggered by
    specifying a large image file as a background. This only effects users
    that have compiled mlterm with the \'gtk\' USE flag, which enables
    gdk-pixbuf support.
  
Impact

    An attacker can create a specially-crafted image file which, when used
    as a background by the victim, can lead to the execution of arbitrary
    code with the privileges of the user running mlterm.
  
Workaround

    Re-compile mlterm without the \'gtk\' USE flag.
  
');
script_set_attribute(attribute:'solution', value: '
    All mlterm users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=x11-terms/mlterm-2.9.2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'https://sourceforge.net/project/shownotes.php?release_id=310416');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0686');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200503-13.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200503-13] mlterm: Integer overflow vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'mlterm: Integer overflow vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "x11-terms/mlterm", unaffected: make_list("ge 2.9.2"), vulnerable: make_list("lt 2.9.2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
