# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200804-11.xml
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
 script_id(31958);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200804-11");
 script_cve_id("CVE-2008-1569");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200804-11 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200804-11
(policyd-weight: Insecure temporary file creation)


    Chris Howells reported that policyd-weight creates and uses the
    "/tmp/.policyd-weight/" directory in an insecure manner.
  
Impact

    A local attacker could exploit this vulnerability to delete arbitrary
    files or change the ownership to the "polw" user via symlink attacks.
  
Workaround

    Set "$LOCKPATH = \'/var/run/policyd-weight/\'" manually in
    "/etc/policyd-weight.conf".
  
');
script_set_attribute(attribute:'solution', value: '
    All policyd-weight users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-filter/policyd-weight-0.1.14.17"
    This version changes the default path for sockets to
    "/var/run/policyd-weight", which is only writable by a privileged user.
    Users need to restart policyd-weight immediately after the upgrade due
    to this change.
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1569');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200804-11.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200804-11] policyd-weight: Insecure temporary file creation');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'policyd-weight: Insecure temporary file creation');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "mail-filter/policyd-weight", unaffected: make_list("ge 0.1.14.17"), vulnerable: make_list("lt 0.1.14.17")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
