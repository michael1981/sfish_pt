# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200404-11.xml
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
 script_id(14476);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200404-11");
 script_cve_id("CVE-2004-0097");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200404-11 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200404-11
(Multiple Vulnerabilities in pwlib)


    Multiple vulnerabilities have been found in the implimentation of protocol
    H.323 contained in pwlib. Most of the vulnerabilies are in the parsing of
    ASN.1 elements which would allow an attacker to use a maliciously crafted
    ASN.1 element to cause unpredictable behavior in pwlib.
  
Impact

    An attacker may cause a denial of service condition or cause a buffer
    overflow that would allow arbitrary code to be executed with root
    privileges.
  
Workaround

    Blocking ports 1719 and 1720 may reduce the likelihood of an attack. All
    users are advised to upgrade to the latest version of the affected package.
  
');
script_set_attribute(attribute:'solution', value: '
    All pwlib users are advised to upgrade to version 1.5.2-r3 or later:
    # emerge sync
    # emerge -pv ">=dev-libs/pwlib-1.5.2-r3"
    # emerge ">=dev-libs/pwlib-1.5.2-r3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0097');
script_set_attribute(attribute: 'see_also', value: 'http://www.uniras.gov.uk/vuls/2004/006489/h323.htm');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200404-11.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200404-11] Multiple Vulnerabilities in pwlib');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Multiple Vulnerabilities in pwlib');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-libs/pwlib", unaffected: make_list("ge 1.5.2-r3"), vulnerable: make_list("le 1.5.2-r2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
