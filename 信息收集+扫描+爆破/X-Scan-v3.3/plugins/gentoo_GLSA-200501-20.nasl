# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-20.xml
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
 script_id(16411);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200501-20");
 script_cve_id("CVE-2004-1288");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200501-20 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200501-20
(o3read: Buffer overflow during file conversion)


    Wiktor Kopec discovered that the parse_html function in o3read.c
    copies any number of bytes into a 1024-byte t[] array.
  
Impact

    Using a specially crafted file, possibly delivered by e-mail or
    over the Web, an attacker may execute arbitrary code with the
    permissions of the user running o3read.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All o3read users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/o3read-0.0.4"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-1288');
script_set_attribute(attribute: 'see_also', value: 'http://tigger.uic.edu/~jlongs2/holes/o3read.txt');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200501-20.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200501-20] o3read: Buffer overflow during file conversion');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'o3read: Buffer overflow during file conversion');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-text/o3read", unaffected: make_list("ge 0.0.4"), vulnerable: make_list("le 0.0.3")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
