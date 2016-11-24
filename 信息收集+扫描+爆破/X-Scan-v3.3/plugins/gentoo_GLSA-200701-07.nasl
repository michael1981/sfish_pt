# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200701-07.xml
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
 script_id(24205);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200701-07");
 script_cve_id("CVE-2006-5870");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200701-07 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200701-07
(OpenOffice.org: EMF/WMF file handling vulnerabilities)


    John Heasman of NGSSoftware has discovered integer overflows in the
    EMR_POLYPOLYGON and EMR_POLYPOLYGON16 processing and an error within
    the handling of META_ESCAPE records.
  
Impact

    An attacker could exploit these vulnerabilities to cause heap overflows
    and potentially execute arbitrary code with the privileges of the user
    running OpenOffice.org by enticing the user to open a document
    containing a malicious WMF/EMF file.
  
Workaround

    There is no known workaround known at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All OpenOffice.org binary users should update to version 2.1.0 or
    later:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-office/openoffice-bin-2.1.0"
    All OpenOffice.org users should update to version 2.0.4 or later:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-office/openoffice-2.0.4"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-5870');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200701-07.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200701-07] OpenOffice.org: EMF/WMF file handling vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'OpenOffice.org: EMF/WMF file handling vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-office/openoffice-bin", unaffected: make_list("ge 2.1.0"), vulnerable: make_list("lt 2.1.0")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "app-office/openoffice", unaffected: make_list("ge 2.0.4"), vulnerable: make_list("lt 2.0.4")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
