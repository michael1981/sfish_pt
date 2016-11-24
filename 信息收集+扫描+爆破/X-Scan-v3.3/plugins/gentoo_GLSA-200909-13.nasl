# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200909-13.xml
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
 script_id(40960);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200909-13");
 script_cve_id("CVE-2009-1959");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200909-13 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200909-13
(irssi: Execution of arbitrary code)


    Nemo discovered an off-by-one error leading to a heap overflow in
    irssi\'s event_wallops() parsing function.
  
Impact

    A remote attacker might entice a user to connect to a malicious IRC
    server, use a man-in-the-middle attack to redirect a user to such a
    server or use ircop rights to send a specially crafted WALLOPS message,
    which might result in the execution of arbitrary code with the
    privileges of the user running irssi.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All irssi users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose =net-irc/irssi-0.8.13-r1
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1959');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200909-13.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200909-13] irssi: Execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'irssi: Execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-irc/irssi", unaffected: make_list("ge 0.8.13-r1"), vulnerable: make_list("lt 0.8.13-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
