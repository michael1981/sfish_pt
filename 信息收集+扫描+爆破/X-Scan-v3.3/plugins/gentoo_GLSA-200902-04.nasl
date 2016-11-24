# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200902-04.xml
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
 script_id(35675);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200902-04");
 script_cve_id("CVE-2008-2383");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200902-04 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200902-04
(xterm: User-assisted arbitrary commands execution)


    Paul Szabo reported an insufficient input sanitization when processing
    Device Control Request Status String (DECRQSS) sequences.
  
Impact

    A remote attacker could entice a user to display a file containing
    specially crafted DECRQSS sequences, possibly resulting in the remote
    execution of arbitrary commands with the privileges of the user viewing
    the file.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All xterm users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=x11-terms/xterm-239"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2383');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200902-04.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200902-04] xterm: User-assisted arbitrary commands execution');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'xterm: User-assisted arbitrary commands execution');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "x11-terms/xterm", unaffected: make_list("ge 239"), vulnerable: make_list("lt 239")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
