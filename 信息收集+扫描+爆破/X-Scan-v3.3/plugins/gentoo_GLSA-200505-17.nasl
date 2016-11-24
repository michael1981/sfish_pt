# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200505-17.xml
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
 script_id(18381);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200505-17");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200505-17 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200505-17
(Qpopper: Multiple Vulnerabilities)


    Jens Steube discovered that Qpopper doesn\'t drop privileges to
    process local files from normal users (CAN-2005-1151). The upstream
    developers discovered that Qpopper can be forced to create group or
    world writeable files (CAN-2005-1152).
  
Impact

    A malicious local attacker could exploit Qpopper to overwrite
    arbitrary files as root or create new files which are group or world
    writeable.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Qpopper users should upgrade to the latest available version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-mail/qpopper-4.0.5-r3"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-1151');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-1152');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200505-17.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200505-17] Qpopper: Multiple Vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Qpopper: Multiple Vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-mail/qpopper", unaffected: make_list("ge 4.0.5-r3"), vulnerable: make_list("lt 4.0.5-r3")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
