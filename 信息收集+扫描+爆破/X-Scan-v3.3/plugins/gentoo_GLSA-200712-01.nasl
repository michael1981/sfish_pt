# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200712-01.xml
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
 script_id(29231);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200712-01");
 script_cve_id("CVE-2007-5200");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200712-01 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200712-01
(Hugin: Insecure temporary file creation)


    Suse Linux reported that Hugin creates the
    "hugin_debug_optim_results.txt" temporary file in an insecure manner.
  
Impact

    A local attacker could exploit this vulnerability with a symlink
    attack, potentially overwriting an arbitrary file with the privileges
    of the user running the application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Hugin users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-gfx/hugin-0.6.1-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5200');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200712-01.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200712-01] Hugin: Insecure temporary file creation');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Hugin: Insecure temporary file creation');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-gfx/hugin", unaffected: make_list("rge 0.6.1-r1", "ge 0.7_beta4-r1"), vulnerable: make_list("lt 0.7_beta4-r1")
)) { security_note(0); exit(0); }
exit(0, "Host is not affected");
