# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200410-26.xml
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
 script_id(15568);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200410-26");
 script_cve_id("CVE-2004-1484");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200410-26 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200410-26
(socat: Format string vulnerability)


    socat contains a syslog() based format string vulnerablility in the
    \'_msg()\' function of \'error.c\'. Exploitation of this bug is only
    possible when socat is run with the \'-ly\' option, causing it to log
    messages to syslog.
  
Impact

    Remote exploitation is possible when socat is used as a HTTP proxy
    client and connects to a malicious server. Local privilege escalation
    can be achieved when socat listens on a UNIX domain socket. Potential
    execution of arbitrary code with the privileges of the socat process is
    possible with both local and remote exploitations.
  
Workaround

    Disable logging to syslog by not using the \'-ly\' option when starting
    socat.
  
');
script_set_attribute(attribute:'solution', value: '
    All socat users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/socat-1.4.0.3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://www.dest-unreach.org/socat/advisory/socat-adv-1.html');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1484');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200410-26.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200410-26] socat: Format string vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'socat: Format string vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/socat", unaffected: make_list("ge 1.4.0.3"), vulnerable: make_list("lt 1.4.0.3")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
