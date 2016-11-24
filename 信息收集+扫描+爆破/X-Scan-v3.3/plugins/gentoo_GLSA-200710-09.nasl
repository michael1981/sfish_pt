# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200710-09.xml
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
 script_id(26980);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200710-09");
 script_cve_id("CVE-2006-1861");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200710-09 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200710-09
(NX 2.1: User-assisted execution of arbitrary code)


    Chris Evans reported an integer overflow within the FreeType PCF font
    file parser (CVE-2006-1861). NX and NX Node are vulnerable to this due
    to shipping XFree86 4.3.0, which includes the vulnerable FreeType code.
  
Impact

    A remote attacker could exploit these integer overflows by enticing a
    user to load a specially crafted PCF font file which might lead to the
    execution of arbitrary code with the privileges of the user on the
    machine running the NX server.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All NX users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/nx-3.0.0"
    All NX Node users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/nxnode-3.0.0-r3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1861');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200607-02.xml');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200710-09.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200710-09] NX 2.1: User-assisted execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'NX 2.1: User-assisted execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/nxnode", unaffected: make_list("ge 3.0.0-r3"), vulnerable: make_list("lt 3.0.0-r3")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "net-misc/nx", unaffected: make_list("ge 3.0.0"), vulnerable: make_list("lt 3.0.0")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
