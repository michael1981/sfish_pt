# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200802-07.xml
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
 script_id(31085);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200802-07");
 script_cve_id("CVE-2008-0008");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200802-07 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200802-07
(Pulseaudio: Privilege escalation)


    Marcus Meissner from SUSE reported that the pa_drop_root() function
    does not properly check the return value of the system calls setuid(),
    seteuid(), setresuid() and setreuid() when dropping its privileges.
  
Impact

    A local attacker could cause a resource exhaustion to make the system
    calls fail, which would cause Pulseaudio to run as root. The attacker
    could then perform actions with root privileges.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Pulseaudio users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-sound/pulseaudio-0.9.9"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0008');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200802-07.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200802-07] Pulseaudio: Privilege escalation');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Pulseaudio: Privilege escalation');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-sound/pulseaudio", unaffected: make_list("ge 0.9.9"), vulnerable: make_list("lt 0.9.9")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
