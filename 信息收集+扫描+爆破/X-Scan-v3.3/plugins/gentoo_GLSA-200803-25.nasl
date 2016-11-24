# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200803-25.xml
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
 script_id(31612);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200803-25");
 script_cve_id("CVE-2008-1199", "CVE-2008-1218");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200803-25 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200803-25
(Dovecot: Multiple vulnerabilities)


    Dovecot uses the group configured via the "mail_extra_groups" setting,
    which should be used to create lockfiles in the /var/mail directory,
    when accessing arbitrary files (CVE-2008-1199). Dovecot does not escape
    TAB characters in passwords when saving them, which might allow for
    argument injection in blocking passdbs such as MySQL, PAM or shadow
    (CVE-2008-1218).
  
Impact

    Remote attackers can exploit the first vulnerability to disclose
    sensitive data, such as the mail of other users, or modify files or
    directories that are writable by group via a symlink attack. Please
    note that the "mail_extra_groups" setting is set to the "mail" group by
    default when the "mbox" USE flag is enabled.
    The second vulnerability can be abused to inject arguments for internal
    fields. No exploitation vectors are known for this vulnerability that
    affect previously stable versions of Dovecot in Gentoo.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Dovecot users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-mail/dovecot-1.0.13-r1"
    This version removes the "mail_extra_groups" option and introduces a
    "mail_privileged_group" setting which is handled safely.
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1199');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1218');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200803-25.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200803-25] Dovecot: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Dovecot: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-mail/dovecot", unaffected: make_list("ge 1.0.13-r1"), vulnerable: make_list("lt 1.0.13-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
