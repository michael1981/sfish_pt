# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200703-13.xml
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
 script_id(24830);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200703-13");
 script_cve_id("CVE-2006-0705");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200703-13 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200703-13
(SSH Communications Security\'s Secure Shell Server: SFTP privilege escalation)


    The SSH Secure Shell Server contains a format string vulnerability in
    the SFTP code that handles file transfers (scp2 and sftp2). In some
    situations, this code passes the accessed filename to the system log.
    During this operation, an unspecified error could allow uncontrolled
    stack access.
  
Impact

    An authenticated system user may be able to exploit this vulnerability
    to bypass command restrictions, or run commands as another user.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    This package is currently masked, there is no upgrade path for the
    3.2.x version, and a license must be purchased in order to update to a
    non-vulnerable version. Because of this, we recommend unmerging this
    package:
    # emerge --ask --verbose --unmerge net-misc/ssh
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0705');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200703-13.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200703-13] SSH Communications Security\'s Secure Shell Server: SFTP privilege escalation');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'SSH Communications Security\'s Secure Shell Server: SFTP privilege escalation');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/ssh", unaffected: make_list(), vulnerable: make_list("lt 4.3.7")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
