# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200712-25.xml
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
 script_id(29822);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200712-25");
 script_cve_id("CVE-2007-4575");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200712-25 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200712-25
(OpenOffice.org: User-assisted arbitrary code execution)


    The HSQLDB engine, as used in Openoffice.org, does not properly enforce
    restrictions to SQL statements.
  
Impact

    A remote attacker could entice a user to open a specially crafted
    document, possibly resulting in the remote execution of arbitrary Java
    code with the privileges of the user running OpenOffice.org.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All OpenOffice.org users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-office/openoffice-2.3.1"
    All OpenOffice.org binary users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-office/openoffice-bin-2.3.1"
    All HSQLDB users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-db/hsqldb-1.8.0.9"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4575');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200712-25.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200712-25] OpenOffice.org: User-assisted arbitrary code execution');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'OpenOffice.org: User-assisted arbitrary code execution');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-office/openoffice-bin", unaffected: make_list("ge 2.3.1"), vulnerable: make_list("lt 2.3.1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "app-office/openoffice", unaffected: make_list("ge 2.3.1"), vulnerable: make_list("lt 2.3.1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "dev-db/hsqldb", unaffected: make_list("ge 1.8.0.9"), vulnerable: make_list("lt 1.8.0.9")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
