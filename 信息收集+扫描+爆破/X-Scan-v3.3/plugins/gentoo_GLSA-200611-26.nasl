# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200611-26.xml
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
 script_id(23762);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200611-26");
 script_cve_id("CVE-2006-5815", "CVE-2006-6170", "CVE-2006-6171");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200611-26 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200611-26
(ProFTPD: Remote execution of arbitrary code)


    Evgeny Legerov discovered a stack-based buffer overflow in the
    s_replace() function in support.c, as well as a buffer overflow in in
    the mod_tls module. Additionally, an off-by-two error related to the
    CommandBufferSize configuration directive was reported.
  
Impact

    An authenticated attacker could exploit the s_replace() vulnerability
    by uploading a crafted .message file or sending specially crafted
    commands to the server, possibly resulting in the execution of
    arbitrary code with the rights of the user running ProFTPD. An
    unauthenticated attacker could send specially crafted data to the
    server with mod_tls enabled which could result in the execution of
    arbitrary code with the rights of the user running ProFTPD. Finally,
    the off-by-two error related to the CommandBufferSize configuration
    directive was fixed - exploitability of this error is disputed. Note
    that the default configuration on Gentoo is to run ProFTPD as an
    unprivileged user, and has mod_tls disabled.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All ProFTPD users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-ftp/proftpd-1.3.0a"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-5815');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-6170');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-6171');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200611-26.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200611-26] ProFTPD: Remote execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ProFTPD: Remote execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-ftp/proftpd", unaffected: make_list("ge 1.3.0a"), vulnerable: make_list("lt 1.3.0a")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
