# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200410-28.xml
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
 script_id(15580);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200410-28");
 script_cve_id("CVE-2004-1628");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200410-28 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200410-28
(rssh: Format string vulnerability)


    Florian Schilhabel from the Gentoo Linux Security Audit Team found a
    format string vulnerability in rssh syslogging of failed commands.
  
Impact

    Using a malicious command, it may be possible for a remote
    authenticated user to execute arbitrary code on the target machine with
    user rights, effectively bypassing any restriction of rssh.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All rssh users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-shells/rssh-2.2.2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://www.pizzashack.org/rssh/security.shtml');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1628');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200410-28.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200410-28] rssh: Format string vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'rssh: Format string vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-shells/rssh", unaffected: make_list("ge 2.2.2"), vulnerable: make_list("lt 2.2.2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
