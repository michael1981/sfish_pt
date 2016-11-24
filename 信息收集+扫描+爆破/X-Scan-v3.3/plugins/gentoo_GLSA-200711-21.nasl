# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200711-21.xml
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
 script_id(28260);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200711-21");
 script_cve_id("CVE-2007-2893", "CVE-2007-2894");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200711-21 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200711-21
(Bochs: Multiple vulnerabilities)


    Tavis Ormandy of the Google Security Team discovered a heap-based
    overflow vulnerability in the NE2000 driver (CVE-2007-2893). He also
    discovered a divide-by-zero error in the emulated floppy disk
    controller (CVE-2007-2894).
  
Impact

    A local attacker in the guest operating system could exploit these
    issues to execute code outside of the virtual machine, or cause Bochs
    to crash.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Bochs users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-emulation/bochs-2.3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-2893');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-2894');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200711-21.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200711-21] Bochs: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Bochs: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-emulation/bochs", unaffected: make_list("ge 2.3"), vulnerable: make_list("lt 2.3")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
