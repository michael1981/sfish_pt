# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200805-01.xml
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
 script_id(32149);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200805-01");
 script_cve_id("CVE-2008-1284");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200805-01 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200805-01
(Horde Application Framework: Multiple vulnerabilities)


    Multiple vulnerabilities have been reported in the Horde Application
    Framework:
    David Collins, Patrick Pelanne and the
    HostGator.com LLC support team discovered that the theme preference
    page does not sanitize POST variables for several options, allowing the
    insertion of NULL bytes and ".." sequences (CVE-2008-1284).
    An
    error exists in the Horde API allowing users to bypass security
    restrictions.
  
Impact

    The first vulnerability can be exploited by a remote attacker to read
    arbitrary files and by remote authenticated attackers to execute
    arbitrary files. The second vulnerability can be exploited by
    authenticated remote attackers to perform restricted operations.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Horde Application Framework users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/horde-3.1.7"
    All horde-groupware users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/horde-groupware-1.0.5"
    All horde-kronolith users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/horde-kronolith-2.1.7"
    All horde-mnemo users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/horde-mnemo-2.1.2"
    All horde-nag users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/horde-nag-2.1.4"
    All horde-webmail users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/horde-webmail-1.0.6"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1284');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200805-01.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200805-01] Horde Application Framework: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Horde Application Framework: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/horde-webmail", unaffected: make_list("ge 1.0.6"), vulnerable: make_list("lt 1.0.6")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "www-apps/horde-nag", unaffected: make_list("ge 2.1.4"), vulnerable: make_list("lt 2.1.4")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "www-apps/horde", unaffected: make_list("ge 3.1.7"), vulnerable: make_list("lt 3.1.7")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "www-apps/horde-kronolith", unaffected: make_list("ge 2.1.7"), vulnerable: make_list("lt 2.1.7")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "www-apps/horde-mnemo", unaffected: make_list("ge 2.1.2"), vulnerable: make_list("lt 2.1.2")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "www-apps/horde-groupware", unaffected: make_list("ge 1.0.5"), vulnerable: make_list("lt 1.0.5")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
