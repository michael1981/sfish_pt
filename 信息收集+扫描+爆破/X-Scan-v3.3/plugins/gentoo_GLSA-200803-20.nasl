# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200803-20.xml
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
 script_id(31446);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200803-20");
 script_cve_id("CVE-2007-4770", "CVE-2007-4771");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200803-20 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200803-20
(International Components for Unicode: Multiple vulnerabilities)


    Will Drewry (Google Security) reported a vulnerability in the regular
    expression engine when using back references to capture \\0 characters
    (CVE-2007-4770). He also found that the backtracking stack size is not
    limited, possibly allowing for a heap-based buffer overflow
    (CVE-2007-4771).
  
Impact

    A remote attacker could submit specially crafted regular expressions to
    an application using the library, possibly resulting in the remote
    execution of arbitrary code with the privileges of the user running the
    application or a Denial of Service.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All International Components for Unicode users should upgrade to the
    latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-libs/icu-3.8.1-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4770');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4771');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200803-20.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200803-20] International Components for Unicode: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'International Components for Unicode: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-libs/icu", unaffected: make_list("ge 3.8.1-r1", "rge 3.6-r2"), vulnerable: make_list("lt 3.8.1-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
