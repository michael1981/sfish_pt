# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200903-09.xml
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
 script_id(35799);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200903-09");
 script_cve_id("CVE-2008-3547", "CVE-2008-3576", "CVE-2008-3577");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200903-09 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200903-09
(OpenTTD: Execution of arbitrary code)


    Multiple buffer overflows have been reported in OpenTTD, when storing
    long for client names (CVE-2008-3547), in the TruncateString function
    in src/gfx.cpp (CVE-2008-3576) and in src/openttd.cpp when processing a
    large filename supplied to the "-g" parameter in the ttd_main function
    (CVE-2008-3577).
  
Impact

    An authenticated attacker could exploit these vulnerabilities to
    execute arbitrary code with the privileges of the OpenTTD server.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All OpenTTD users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=games-simulation/openttd-0.6.3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3547');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3576');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3577');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200903-09.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200903-09] OpenTTD: Execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'OpenTTD: Execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "games-simulation/openttd", unaffected: make_list("ge 0.6.3"), vulnerable: make_list("lt 0.6.3")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
