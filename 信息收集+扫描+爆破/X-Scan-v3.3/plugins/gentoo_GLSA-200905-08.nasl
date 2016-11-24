# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200905-08.xml
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
 script_id(38920);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200905-08");
 script_cve_id("CVE-2009-0159", "CVE-2009-1252");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200905-08 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200905-08
(NTP: Remote execution of arbitrary code)


    Multiple vulnerabilities have been found in the programs included in
    the NTP package:
    Apple Product Security reported a
    boundary error in the cookedprint() function in ntpq/ntpq.c, possibly
    leading to a stack-based buffer overflow (CVE-2009-0159).
    Chris Ries of CMU reported a boundary error within the
    crypto_recv() function in ntpd/ntp_crypto.c, possibly leading to a
    stack-based buffer overflow (CVE-2009-1252).
  
Impact

    A remote attacker might send a specially crafted package to a machine
    running ntpd, possibly resulting in the remote execution of arbitrary
    code with the privileges of the user running the daemon, or a Denial of
    Service. NOTE: Successful exploitation requires the "autokey" feature
    to be enabled. This feature is only available if NTP was built with the
    \'ssl\' USE flag.
    Furthermore, a remote attacker could entice a user into connecting to a
    malicious server using ntpq, possibly resulting in the remote execution
    of arbitrary code with the privileges of the user running the
    application, or a Denial of Service.
  
Workaround

    You can protect against CVE-2009-1252 by disabling the \'ssl\' USE flag
    and recompiling NTP.
  
');
script_set_attribute(attribute:'solution', value: '
    All NTP users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/ntp-4.2.4_p7"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0159');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1252');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200905-08.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200905-08] NTP: Remote execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'NTP: Remote execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/ntp", unaffected: make_list("ge 4.2.4_p7"), vulnerable: make_list("lt 4.2.4_p7")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
