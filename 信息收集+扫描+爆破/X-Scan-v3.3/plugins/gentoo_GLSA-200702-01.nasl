# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200702-01.xml
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
 script_id(24350);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200702-01");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200702-01 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200702-01
(Samba: Multiple vulnerabilities)


    A format string vulnerability exists in the VFS module when handling
    AFS file systems and an infinite loop has been discovered when handling
    file rename operations.
  
Impact

    A user with permission to write to a shared AFS file system may be able
    to compromise the smbd process and execute arbitrary code with the
    permissions of the daemon. The infinite loop could be abused to consume
    excessive resources on the smbd host, denying service to legitimate
    users.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Samba users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-fs/samba-3.0.24"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://samba.org/samba/security/CVE-2007-0452.html');
script_set_attribute(attribute: 'see_also', value: 'http://samba.org/samba/security/CVE-2007-0454.html');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200702-01.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200702-01] Samba: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Samba: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-fs/samba", unaffected: make_list("ge 3.0.24"), vulnerable: make_list("lt 3.0.24")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
