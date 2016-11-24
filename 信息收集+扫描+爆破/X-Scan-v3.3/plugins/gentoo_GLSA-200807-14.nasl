# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200807-14.xml
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
 script_id(33780);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200807-14");
 script_cve_id("CVE-2008-1628");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200807-14 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200807-14
(Linux Audit: Buffer overflow)


    A stack-based buffer overflow has been reported in the
    audit_log_user_command() function in the file lib/audit_logging.c when
    processing overly long arguments.
  
Impact

    A local attacker could execute a specially crafted command on the host
    running Linux Audit, possibly resulting in the execution of arbitrary
    code with the privileges of the user running Linux Audit.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Linux Audit users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=sys-process/audit-1.7.3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:M/Au:S/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1628');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200807-14.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200807-14] Linux Audit: Buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Linux Audit: Buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "sys-process/audit", unaffected: make_list("ge 1.7.3"), vulnerable: make_list("lt 1.7.3")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
