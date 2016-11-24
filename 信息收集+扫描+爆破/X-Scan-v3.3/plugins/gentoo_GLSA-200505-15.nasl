# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200505-15.xml
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
 script_id(18379);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200505-15");
 script_cve_id("CVE-2005-1704", "CVE-2005-1705");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200505-15 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200505-15
(gdb: Multiple vulnerabilities)


    Tavis Ormandy of the Gentoo Linux Security Audit Team discovered an
    integer overflow in the BFD library, resulting in a heap overflow. A
    review also showed that by default, gdb insecurely sources
    initialisation files from the working directory.
  
Impact

    Successful exploitation would result in the execution of arbitrary code
    on loading a specially crafted object file or the execution of
    arbitrary commands.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All gdb users should upgrade to the latest stable version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=sys-devel/gdb-6.3-r3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1704');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1705');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200505-15.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200505-15] gdb: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'gdb: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "sys-devel/gdb", unaffected: make_list("ge 6.3-r3"), vulnerable: make_list("lt 6.3-r3")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
