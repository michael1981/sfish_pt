# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200812-13.xml
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
 script_id(35101);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200812-13");
 script_cve_id("CVE-2008-2237", "CVE-2008-2238", "CVE-2008-4937");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200812-13 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200812-13
(OpenOffice.org: Multiple vulnerabilities)


    Two heap-based buffer overflows when processing WMF files
    (CVE-2008-2237) and EMF files (CVE-2008-2238) were discovered. Dmitry
    E. Oboukhov also reported an insecure temporary file usage within the
    senddoc script (CVE-2008-4937).
  
Impact

    A remote attacker could entice a user to open a specially crafted
    document, resulting in the remote execution of arbitrary code. A local
    attacker could perform symlink attacks to overwrite arbitrary files on
    the system. Both cases happen with the privileges of the user running
    the application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All OpenOffice.org users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-office/openoffice-3.0.0"
    All OpenOffice.org binary users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-office/openoffice-bin-3.0.0"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2237');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2238');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4937');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200812-13.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200812-13] OpenOffice.org: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'OpenOffice.org: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-office/openoffice-bin", unaffected: make_list("ge 3.0.0"), vulnerable: make_list("lt 3.0.0")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "app-office/openoffice", unaffected: make_list("ge 3.0.0"), vulnerable: make_list("lt 3.0.0")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
