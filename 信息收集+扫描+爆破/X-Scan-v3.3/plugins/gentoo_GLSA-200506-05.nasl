# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200506-05.xml
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
 script_id(18445);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200506-05");
 script_cve_id("CVE-2005-1941");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200506-05 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200506-05
(SilverCity: Insecure file permissions)


    The SilverCity package installs three executable files with insecure
    permissions.
  
Impact

    A local attacker could modify the executable files, causing arbitrary
    code to be executed with the permissions of an unsuspecting SilverCity
    user.
  
Workaround

    There are no known workarounds at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All SilverCity users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/silvercity-0.9.5-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1941');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200506-05.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200506-05] SilverCity: Insecure file permissions');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'SilverCity: Insecure file permissions');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-text/silvercity", unaffected: make_list("ge 0.9.5-r1"), vulnerable: make_list("lt 0.9.5-r1")
)) { security_note(0); exit(0); }
exit(0, "Host is not affected");
