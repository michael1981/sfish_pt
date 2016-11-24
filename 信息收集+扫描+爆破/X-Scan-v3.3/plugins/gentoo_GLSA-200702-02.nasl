# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200702-02.xml
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
 script_id(24351);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200702-02");
 script_cve_id("CVE-2006-6563");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200702-02 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200702-02
(ProFTPD: Local privilege escalation)


    A flaw exists in the mod_ctrls module of ProFTPD, normally used to
    allow FTP server administrators to configure the daemon at runtime.
  
Impact

    An FTP server administrator permitted to interact with mod_ctrls could
    potentially compromise the ProFTPD process and execute arbitrary code
    with the privileges of the FTP Daemon, which is normally the root user.
  
Workaround

    Disable mod_ctrls, or ensure only trusted users can access this
    feature.
  
');
script_set_attribute(attribute:'solution', value: '
    All ProFTPD users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-ftp/proftpd-1.3.1_rc1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:M/Au:S/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-6563');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200702-02.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200702-02] ProFTPD: Local privilege escalation');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ProFTPD: Local privilege escalation');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-ftp/proftpd", unaffected: make_list("ge 1.3.1_rc1"), vulnerable: make_list("lt 1.3.1_rc1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
