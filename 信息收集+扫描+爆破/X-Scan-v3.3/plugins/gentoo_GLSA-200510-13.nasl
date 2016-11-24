# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200510-13.xml
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
 script_id(20033);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200510-13");
 script_cve_id("CVE-2005-3291");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200510-13 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200510-13
(SPE: Insecure file permissions)


    It was reported that due to an oversight all SPE\'s files are set as
    world-writeable.
  
Impact

    A local attacker could modify the executable files, causing arbitrary
    code to be executed with the permissions of the user running SPE.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All SPE users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose dev-util/spe
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3291');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200510-13.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200510-13] SPE: Insecure file permissions');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'SPE: Insecure file permissions');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-util/spe", unaffected: make_list("ge 0.7.5c-r1", "rge 0.5.1f-r1"), vulnerable: make_list("lt 0.7.5c-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
