# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200908-06.xml
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
 script_id(40631);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200908-06");
 script_cve_id("CVE-2009-2850");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200908-06 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200908-06
(CDF: User-assisted execution of arbitrary code)


    Leon Juranic reported multiple heap-based buffer overflows for instance
    in the ReadAEDRList64(), SearchForRecord_r_64(), LastRecord64(), and
    CDFsel64() functions.
  
Impact

    A remote attacker could entice a user to open a specially crafted CDF
    file, possibly resulting in the execution of arbitrary code with the
    privileges of the user running the application, or a Denial of Service.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All CDF users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose =sci-libs/cdf-3.3.0
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2850');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200908-06.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200908-06] CDF: User-assisted execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'CDF: User-assisted execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "sci-libs/cdf", unaffected: make_list("ge 3.3.0"), vulnerable: make_list("lt 3.3.0")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
