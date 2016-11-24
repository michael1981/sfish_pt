# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-32.xml
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
 script_id(14809);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200409-32");
 script_cve_id("CVE-2004-0880", "CVE-2004-0881");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200409-32 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200409-32
(getmail: Filesystem overwrite vulnerability)


    David Watson discovered a vulnerability in getmail when it is
    configured to run as root and deliver mail to the maildirs/mbox files
    of untrusted local users. A malicious local user can then exploit a
    race condition, or a similar symlink attack, and potentially cause
    getmail to create or overwrite files in any directory on the system.
  
Impact

    An untrusted local user could potentially create or overwrite files in
    any directory on the system. This vulnerability may also be exploited
    to have arbitrary commands executed as root.
  
Workaround

    Do not run getmail as a privileged user; or, in version 4, use an
    external MDA with explicitly configured user and group privileges.
  
');
script_set_attribute(attribute:'solution', value: '
    All getmail users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=net-mail/getmail-4.2.0"
    # emerge ">=net-mail/getmail-4.2.0"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://www.qcc.ca/~charlesc/software/getmail-4/CHANGELOG');
script_set_attribute(attribute: 'see_also', value: 'http://article.gmane.org/gmane.mail.getmail.user/1430');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0880');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0881');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200409-32.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200409-32] getmail: Filesystem overwrite vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'getmail: Filesystem overwrite vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-mail/getmail", unaffected: make_list("ge 4.2.0"), vulnerable: make_list("lt 4.2.0")
)) { security_note(0); exit(0); }
exit(0, "Host is not affected");
