# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200903-19.xml
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
 script_id(35817);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200903-19");
 script_cve_id("CVE-2008-4482");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200903-19 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200903-19
(Xerces-C++: Denial of Service)


    Frank Rast reported that the XML parser in Xerces-C++ does not
    correctly handle an XML schema definition with a large maxOccurs value,
    which triggers excessive memory consumption during the validation of an
    XML file.
  
Impact

    A remote attacker could entice a user or automated system to validate
    an XML file using a specially crafted XML schema file, leading to a
    Denial of Service (stack consumption and crash).
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Xerces-C++ users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-libs/xerces-c-3.0.0-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4482');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200903-19.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200903-19] Xerces-C++: Denial of Service');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Xerces-C++: Denial of Service');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-libs/xerces-c", unaffected: make_list("ge 3.0.0-r1"), vulnerable: make_list("lt 3.0.0-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
