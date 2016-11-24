# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200810-02.xml
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
 script_id(34383);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200810-02");
 script_cve_id("CVE-2008-4394");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200810-02 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200810-02
(Portage: Untrusted search path local root vulnerability)


    The Gentoo Security Team discovered that several ebuilds, such as
    sys-apps/portage, net-mail/fetchmail or app-editors/leo execute Python
    code using "python -c", which includes the current working directory in
    Python\'s module search path. For several ebuild functions, Portage did
    not change the working directory from emerge\'s working directory.
  
Impact

    A local attacker could place a specially crafted Python module in a
    directory (such as /tmp) and entice the root user to run commands such
    as "emerge sys-apps/portage" from that directory, resulting in the
    execution of arbitrary Python code with root privileges.
  
Workaround

    Do not run "emerge" from untrusted working directories.
  
');
script_set_attribute(attribute:'solution', value: '
    All Portage users should upgrade to the latest version:
    # cd /root
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=sys-apps/portage-2.1.4.5"
    NOTE: To upgrade to Portage 2.1.4.5 using 2.1.4.4 or prior, you must
    run emerge from a trusted working directory, such as "/root".
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4394');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200810-02.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200810-02] Portage: Untrusted search path local root vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Portage: Untrusted search path local root vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "sys-apps/portage", unaffected: make_list("ge 2.1.4.5"), vulnerable: make_list("lt 2.1.4.5")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
