# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200607-12.xml
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
 script_id(22120);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200607-12");
 script_cve_id("CVE-2006-2199", "CVE-2006-2198", "CVE-2006-3117");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200607-12 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200607-12
(OpenOffice.org: Multiple vulnerabilities)


    Internal security audits by OpenOffice.org have discovered three
    security vulnerabilities related to Java applets, macros and the XML
    file format parser.
    Specially crafted Java applets can
    break through the "sandbox".
    Specially crafted macros make it
    possible to inject BASIC code into documents which is executed when the
    document is loaded.
    Loading a malformed XML file can cause a
    buffer overflow.
  
Impact

    An attacker might exploit these vulnerabilities to escape the Java
    sandbox, execute arbitrary code or BASIC code with the permissions of
    the user running OpenOffice.org.
  
Workaround

    Disabling Java applets will protect against the vulnerability in the
    handling of Java applets. There are no workarounds for the macro and
    file format vulnerabilities.
  
');
script_set_attribute(attribute:'solution', value: '
    All OpenOffice.org users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-office/openoffice-2.0.3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://www.openoffice.org/security/bulletin-20060629.html');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=2006-2199');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=2006-2198');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=2006-3117');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200607-12.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200607-12] OpenOffice.org: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'OpenOffice.org: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-office/openoffice-bin", unaffected: make_list("ge 2.0.3"), vulnerable: make_list("lt 2.0.3")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "app-office/openoffice", unaffected: make_list("ge 2.0.3"), vulnerable: make_list("lt 2.0.3")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
