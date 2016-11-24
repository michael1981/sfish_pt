# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200711-11.xml
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
 script_id(27846);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200711-11");
 script_cve_id("CVE-2007-5198", "CVE-2007-5623");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200711-11 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200711-11
(Nagios Plugins: Two buffer overflows)


    fabiodds reported a boundary checking error in the "check_snmp" plugin
    when processing SNMP "GET" replies that could lead to a stack-based
    buffer overflow (CVE-2007-5623). Nobuhiro Ban reported a boundary
    checking error in the redir() function of the "check_http" plugin when
    processing HTTP "Location:" header information which might lead to a
    buffer overflow (CVE-2007-5198).
  
Impact

    A remote attacker could exploit these vulnerabilities to execute
    arbitrary code with the privileges of the user running Nagios or cause
    a Denial of Service by (1) sending a specially crafted SNMP "GET" reply
    to the Nagios daemon or (2) sending an overly long string in the
    "Location:" header of an HTTP reply. Note that to exploit (2), the
    malicious or compromised web server has to be configured in Nagios and
    the "-f" (follow) option has to be enabled.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All users of the Nagios Plugins should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-analyzer/nagios-plugins-1.4.10-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5198');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5623');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200711-11.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200711-11] Nagios Plugins: Two buffer overflows');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Nagios Plugins: Two buffer overflows');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-analyzer/nagios-plugins", unaffected: make_list("ge 1.4.10-r1"), vulnerable: make_list("lt 1.4.10-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
