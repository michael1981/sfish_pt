# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200801-14.xml
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
 script_id(30119);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200801-14");
 script_cve_id("CVE-2005-4790");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200801-14 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200801-14
(Blam: User-assisted execution of arbitrary code)


    The "/usr/bin/blam" script sets the "LD_LIBRARY_PATH" environment
    variable incorrectly, which might result in the current working
    directory (.) being included when searching for dynamically linked
    libraries of the Mono Runtime application.
  
Impact

    A local attacker could entice a user to run Blam in a directory
    containing a specially crafted library file which could result in the
    execution of arbitrary code with the privileges of the user running
    Blam.
  
Workaround

    Do not run Blam from an untrusted working directory.
  
');
script_set_attribute(attribute:'solution', value: '
    All Blam users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-news/blam-1.8.4"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-4790');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200801-14.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200801-14] Blam: User-assisted execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Blam: User-assisted execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-news/blam", unaffected: make_list("ge 1.8.4"), vulnerable: make_list("lt 1.8.4")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
